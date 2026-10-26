from pathlib import Path
import json
import os
import re
import random
import asyncio
import io
import base64
import traceback
import html as html_lib
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
import discord
from typing import Optional
from discord import app_commands
from discord.ext import commands, tasks
import chat_exporter

# =====================================================================
# --- TRANSCRIPT WEBSITE PUBLISHER ---
# Publishes each saved ticket transcript, encrypted, to a GitHub Pages site.
# Needs transcript_site.json next to this file. If it is missing or invalid the
# feature simply stays off and the bot runs normally. Test it with: -sitetest
# =====================================================================
import gzip
import secrets
import aiohttp
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    _SITE_CRYPTO_OK = True
except ImportError:
    _SITE_CRYPTO_OK = False

SITE_CONFIG_FILE = str(Path(__file__).resolve().parent / "transcript_site.json")
ITERATIONS = 250_000
API = "https://api.github.com"
META_PATH = "data/meta.json"
INDEX_PATH = "data/index.bin"


class _Conflict(Exception):
    """The file changed on GitHub between our read and our write."""


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def _seal(key: bytes, plaintext: bytes) -> bytes:
    """gzip -> AES-GCM. Output layout: 12-byte IV + ciphertext + 16-byte tag."""
    iv = secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, gzip.compress(plaintext, 9), None)


def _open(key: bytes, blob: bytes) -> bytes:
    return gzip.decompress(AESGCM(key).decrypt(blob[:12], blob[12:], None))


class TranscriptPublisher:
    def __init__(self, token: str, repo: str, password: str, branch: str = "main", site_url: str = None):
        self.token = token
        self.repo = repo          # "owner/name"
        self.password = password
        self.branch = branch
        owner, _, name = repo.partition("/")
        if site_url:
            self.site_url = site_url
        elif name.lower() == f"{owner.lower()}.github.io":
            self.site_url = f"https://{owner.lower()}.github.io/"
        else:
            self.site_url = f"https://{owner.lower()}.github.io/{name}/"
        self._key = None
        self._lock = None             # created lazily inside the bot's event loop

    @classmethod
    def load(cls, path: str = SITE_CONFIG_FILE):
        """Load the GitHub publisher configuration; no website password is required."""
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
            return cls(cfg["token"], cfg["repo"], cfg.get("password", ""), cfg.get("branch", "main"), cfg.get("site_url"))
        except FileNotFoundError:
            print(f"[transcript-site] {path} not found; website publishing is disabled.")
        except (KeyError, ValueError) as exc:
            print(f"[transcript-site] {path} is invalid ({exc!r}); website publishing is disabled.")
        return None
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
            return cls(cfg["token"], cfg["repo"], cfg["password"], cfg.get("branch", "main"), cfg.get("site_url"))
        except FileNotFoundError:
            print(f"[transcript-site] {path} not found; website publishing is disabled.")
        except (KeyError, ValueError) as exc:
            print(f"[transcript-site] {path} is invalid ({exc!r}); website publishing is disabled.")
        return None

    # ---------- GitHub contents API ----------
    def _session(self):
        return aiohttp.ClientSession(
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=aiohttp.ClientTimeout(total=60),
        )

    def _url(self, path):
        return f"{API}/repos/{self.repo}/contents/{path}"

    async def _get(self, s, path):
        """Return (bytes, sha), or (None, None) if the file doesn't exist."""
        async with s.get(self._url(path), params={"ref": self.branch}) as r:
            if r.status == 404:
                return None, None
            r.raise_for_status()
            info = await r.json()
        if info.get("content"):
            return base64.b64decode(info["content"]), info["sha"]
        # Files over 1 MB come back without content; fetch the raw bytes instead.
        async with s.get(self._url(path), params={"ref": self.branch},
                         headers={"Accept": "application/vnd.github.raw+json"}) as r:
            r.raise_for_status()
            return await r.read(), info["sha"]

    async def _put(self, s, path, data: bytes, message: str, sha: str = None):
        body = {"message": message, "content": base64.b64encode(data).decode(), "branch": self.branch}
        if sha:
            body["sha"] = sha
        async with s.put(self._url(path), json=body) as r:
            if r.status in (409, 422):
                raise _Conflict(path)
            r.raise_for_status()

    async def _delete(self, s, path, message: str):
        _, sha = await self._get(s, path)
        if sha:
            async with s.delete(self._url(path),
                                json={"message": message, "sha": sha, "branch": self.branch}) as r:
                r.raise_for_status()

    # ---------- encryption key ----------
    async def _ensure_key(self, s) -> bytes:
        if self._key:
            return self._key
        raw, _ = await self._get(s, META_PATH)
        if raw is None:
            meta = {"v": 1, "salt": secrets.token_hex(16), "iter": ITERATIONS}
            try:
                await self._put(s, META_PATH, json.dumps(meta).encode(), "Initialise transcript site")
            except _Conflict:
                raw, _ = await self._get(s, META_PATH)
                meta = json.loads(raw)
        else:
            meta = json.loads(raw)
        loop = asyncio.get_running_loop()
        self._key = await loop.run_in_executor(
            None, _derive_key, self.password, bytes.fromhex(meta["salt"]), int(meta["iter"]))
        return self._key

    def link_for(self, file_id: str) -> str:
        """Return a direct link that opens only this transcript."""
        return self.site_url.rstrip("/") + "/?id=" + file_id

    # ---------- publishing ----------
    async def publish(self, html: bytes, entry: dict):
        """Upload one transcript as HTML and maintain a plain JSON index for compatibility."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            async with self._session() as session:
                file_id = secrets.token_hex(12)
                await self._put(session, f"data/t/{file_id}.html", html,
                                f"Add transcript for ticket #{entry['ticket']}")
                entry = dict(entry, id=file_id,
                             saved_at=datetime.now(timezone.utc).isoformat())
                for attempt in range(5):
                    raw, sha = await self._get(session, INDEX_PATH)
                    # Migrate gracefully if an older encrypted index is present:
                    # the direct-link viewer does not need an index at all.
                    try:
                        entries = json.loads(raw) if raw else []
                    except Exception:
                        entries = []
                    same = lambda e: e.get("guild") == entry["guild"] and e.get("ticket") == entry["ticket"]
                    entries = [e for e in entries if not same(e)] + [entry]
                    entries.sort(key=lambda e: e.get("saved_at", ""), reverse=True)
                    try:
                        await self._put(session, INDEX_PATH, json.dumps(entries).encode(),
                                        f"Update index (ticket #{entry['ticket']})", sha)
                        break
                    except _Conflict:
                        await asyncio.sleep(1 + attempt)
                else:
                    raise RuntimeError("Could not update the transcript index after 5 attempts")
                return file_id

    async def diagnose(self) -> str:
        """Check each link in the chain and return a plain-English report."""
        out = []
        ok = lambda t: out.append("\u2705 " + t)
        bad = lambda t: out.append("\u274c " + t)
        warn = lambda t: out.append("\u26a0\ufe0f " + t)
        try:
            async with self._session() as s:
                async with s.get(f"{API}/repos/{self.repo}") as r:
                    if r.status == 200:
                        info = await r.json()
                        ok(f"Repo found: {info.get('full_name')} ({'private' if info.get('private') else 'public'})")
                        if info.get("default_branch") != self.branch:
                            warn(f"Config says branch '{self.branch}' but the repo's default branch is "
                                 f"'{info.get('default_branch')}'. Change \"branch\" if that is the one Pages uses.")
                    elif r.status == 401:
                        bad("GitHub rejected the token. It is mistyped or expired; create a new one.")
                        return "\n".join(out)
                    elif r.status == 404:
                        bad("Repo not found. Either \"repo\" is misspelled (it must look like username/reponame) "
                            "or the token was not given access to that repo.")
                        return "\n".join(out)
                    else:
                        bad(f"GitHub answered {r.status} when looking up the repo.")
                        return "\n".join(out)

                try:
                    test = "data/selftest.txt"
                    _, sha = await self._get(s, test)
                    await self._put(s, test, b"ok", "Transcript site self-test", sha)
                    await self._delete(s, test, "Remove self-test file")
                    ok("The token can write to the repo")
                except Exception as exc:
                    bad(f"The token cannot write to the repo ({getattr(exc, 'status', exc)}). In the token "
                        "settings, set Repository permissions > Contents to Read and write.")
                    return "\n".join(out)

                try:
                    await self._ensure_key(s)
                    ok("Encryption is ready")
                except Exception as exc:
                    bad(f"Encryption setup failed: {exc!r}")

                raw, _ = await self._get(s, "index.html")
                if raw is None:
                    bad("index.html is not in the repo's top folder. Upload it there.")
                else:
                    ok("index.html is in the repo")

                async with s.get(f"{API}/repos/{self.repo}/pages") as r:
                    if r.status == 200:
                        ok(f"GitHub Pages is on: {(await r.json()).get('html_url')}")
                    elif r.status == 404:
                        bad("GitHub Pages does not look turned on (repo Settings > Pages > Deploy from a branch).")
                    else:
                        warn("Could not check GitHub Pages. Confirm it is on in repo Settings > Pages.")
        except Exception as exc:
            bad(f"Could not reach GitHub: {exc!r}")
        return "\n".join(out)

    async def publish_ticket(self, channel, data: dict, html: bytes):
        """Called by the bot after a transcript is built. Returns the website link, or None on failure. Never raises."""
        try:
            guild = channel.guild

            def who(user_id):
                member = guild.get_member(int(user_id)) if user_id else None
                return member.display_name if member else str(user_id or "unknown")

            file_id = await self.publish(html, {
                "guild": str(guild.id),
                "ticket": int(data.get("number", 0)),
                "category": str(data.get("category_key") or "ticket"),
                "creator": who(data.get("creator_id")),
                "closed_by": who(data.get("closed_by")),
                "closed_at": data.get("closed_at") or "",
            })
            print(f"[transcript-site] published ticket #{data.get('number')}")
            return self.link_for(file_id)
        except Exception as exc:
            print(f"[transcript-site] publish failed for ticket #{data.get('number')}: {exc!r}")
            return None


site_publisher = TranscriptPublisher.load()
# ---------------------------------------------------------------------

# --- TIME ZONE (CENTRAL TIME) ---
# America/Chicago switches between CST and CDT automatically. If this fails to
# load on a minimal host, install the tz database with: pip install tzdata
try:
    CENTRAL_TZ = ZoneInfo("America/Chicago")
except Exception as _tz_exc:
    print(f"WARNING: could not load America/Chicago ({_tz_exc!r}); falling back to UTC. Run: pip install tzdata")
    CENTRAL_TZ = timezone.utc


def central_now() -> datetime:
    """Current time in Central Time (timezone-aware; .timestamp() is still a normal unix time)."""
    return datetime.now(CENTRAL_TZ)


with open("token.txt") as f:
    TOKEN = f.read().strip()

# --- BOT CONFIGURATION & INITIALIZATION ---
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

MOD_DATA_FILE = "moderation_data.json"
ECONOMY_DATA_FILE = "economy_data.json"
MOD_LOG_CHANNEL_ID = 1532483516405780530
CIVRES_APPEAL_CHANNEL_ID = 1562924110626033734
# /modreq destinations & pings
MODREQ_STANDARD_CHANNEL_ID = 1542385006406803466   # mod-requests: Warn / Strike / Infraction requests
MODREQ_STANDARD_PING_ROLE = 1532987896414339072
MODREQ_BAN_CHANNEL_ID = 1544526297294839899        # ban-submissions
MODREQ_BAN_PING_ROLE = 1535871041304404048

# --- ROLE IDS & PAYOUT CONFIGURATION ---
ROLE_BOOSTER = 1532452726988996658          # ($5,000)
ROLE_PUBLIC_SERVICES = 1532457174188429312   # ($1,500)
ROLE_DEPT_HEAD = 1533947697810116771
ROLE_SUPERVISOR = 1532456149901639791  # Supervisor
ROLE_STAFF = 1532987896414339072
ROLE_VERIFIED_MEMBER = 1533960357155049675

# Cooldown Bypass Role ID
ROLE_NO_COOLDOWN = 1532452702603444356

# Authorized Role IDs for Specific Commands
AUTHORIZED_PREFIX_ROLE = 1532987896414339072
MODERATOR_ROLE_ID = 1532455935455531252
SERVER_STAFF_ROLE_ID = 1532987896414339072
ADMINISTRATION_ROLE_ID = 1535871041304404048
STAFF_INFRACT_ROLES = [1532455433707589814, 1532452702603444356]
STAFF_BLACKLIST_ROLES = [1532453040974594089, 1532452702603444356]

PUNISHMENT_ROLES = {
    "Warn 1": "Warning 1",
    "Warn 2": "Warning 2",
    "Strike 1": "Strike 1",
    "Strike 2": "Strike 2",
    "Infract 1": "Infraction 1",
    "Infract 2": "Infraction 2",
    "Civ Restriction 1": "Civilian Restriction 1",
    "Civ Restriction 2": "Civilian Restriction 2",
    "Staff Infraction 1": "Staff Infraction 1",
    "Staff Infraction 2": "Staff Infraction 2",
    "Staff Infraction 3": "Staff Infraction 3",
    "Staff Blacklist": "Staff Blacklist",
}

# --- DATA LOAD/SAVE HELPERS (WITH JSON SAFEGARD) ---
def load_json(filepath, default_data):
    if not os.path.exists(filepath):
        return default_data
    try:
        with open(filepath, "r") as f:
            content = f.read().strip()
            if not content:  # Catches empty files (0 bytes)
                return default_data
            return json.loads(content)
    except (json.JSONDecodeError, Exception) as e:
        print(f"Warning: Failed to parse {filepath} ({e}). Returning default data.")
        return default_data

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

def load_data():
    return load_json(MOD_DATA_FILE, {"next_case": 1000, "users": {}})

def save_data(data):
    save_json(MOD_DATA_FILE, data)

def load_economy():
    return load_json(ECONOMY_DATA_FILE, {})

def save_economy(data):
    save_json(ECONOMY_DATA_FILE, data)

# --- HELPER FOR RAW COMPONENTS V2 CONTAINER ---
def build_v2_payload(title: str = None, body_text: str = None, inner_sections: list = None):
    container_components = []

    if title:
        container_components.append({
            "type": 10,
            "content": f"# **{title}**"
        })

    if body_text:
        container_components.append({
            "type": 10,
            "content": body_text
        })

    if inner_sections:
        for section in inner_sections:
            if section and section.strip():
                container_components.append({
                    "type": 14,
                    "spacing": 1
                })
                container_components.append({
                    "type": 10,
                    "content": section.strip()
                })

    return [{
        "type": 17,
        "components": container_components
    }]


async def fetch_raw_message(client: discord.Client, channel_id: int, message_id: int) -> dict:
    """Fetch a message straight from the API as raw JSON.

    We rely on this instead of discord.py's parsed `message.components` for
    Component V2 detection/editing because parsing support for the type 17
    container varies between discord.py versions - the raw payload is always
    accurate regardless of library version.
    """
    return await client.http.request(
        discord.http.Route(
            'GET', '/channels/{channel_id}/messages/{message_id}',
            channel_id=channel_id, message_id=message_id
        )
    )


def parse_v2_container(raw_components: list):
    """Reverse of build_v2_payload(): pulls (title, body_text, sections) back
    out of a raw type 17 container's component list, so an existing V2
    message can be re-opened for editing with its current content pre-filled."""
    title, body, sections = None, None, []

    container = None
    for comp in (raw_components or []):
        if comp.get("type") == 17:
            container = comp
            break
    if not container:
        return title, body, sections

    items = container.get("components", [])
    idx = 0

    if idx < len(items) and items[idx].get("type") == 10:
        text = items[idx].get("content", "") or ""
        if text.startswith("# **") and text.endswith("**"):
            title = text[4:-2]
            idx += 1

    if idx < len(items) and items[idx].get("type") == 10:
        body = items[idx].get("content", "")
        idx += 1

    while idx < len(items):
        item = items[idx]
        if item.get("type") == 10:
            sections.append(item.get("content", ""))
        idx += 1

    return title, body, sections


async def send_v2_dm(bot: commands.Bot, user: discord.User, title: str, body_text: str, inner_sections: list = None):
    try:
        dm_channel = user.dm_channel or await user.create_dm()
        components_payload = build_v2_payload(title, body_text, inner_sections)
        
        await bot.http.request(
            discord.http.Route('POST', '/channels/{channel_id}/messages', channel_id=dm_channel.id),
            json={"components": components_payload, "flags": 32768}
        )
        return True
    except Exception as e:
        print(f"Failed to send V2 DM to {user.name}: {e}")
        return False


# --- LOGGING HELPER ---
async def log_to_channel(bot: commands.Bot, guild: discord.Guild, channel_id: int, title: str, description: str, color: int, footer_text: str):
    channel = guild.get_channel(channel_id)
    if not channel:
        try:
            channel = await guild.fetch_channel(channel_id)
        except Exception:
            print(f"Could not find log channel: {channel_id}")
            return

    embed = discord.Embed(title=title, description=description, color=color)
    embed.set_footer(text=footer_text)
    await channel.send(embed=embed)


# --- ECONOMY LOGGING ---
# Every economy event (work, collect, deposit, withdraw, pay, admin add/remove,
# blackjack results, shop purchases, citation/license/warrant payments) is sent here.
ECO_LOG_CHANNEL_ID = 1561936262535839744


async def log_economy(guild, title: str, description: str, color: int = 0x596744, footer: str = "Economy Log"):
    """Send an economy event to the economy log channel. Never raises."""
    if guild is None:
        return
    try:
        await log_to_channel(
            bot=bot,
            guild=guild,
            channel_id=ECO_LOG_CHANNEL_ID,
            title=title,
            description=description,
            color=color,
            footer_text=footer,
        )
    except Exception as exc:
        print(f"Economy log failed: {exc!r}")


# ---------- GVRG TICKET SYSTEM ----------

if not hasattr(discord.ui, "LayoutView"):
    raise RuntimeError(
        "This GVRG ticket bot uses Discord Components V2 and requires discord.py 2.6+. "
        "Upgrade discord.py before starting the bot."
    )

# ============================================================
# TEST TICKET BOT
# Ticket Tool-style custom ticket system for discord.py 2.6+ (Components V2)
# Python 3.13 compatible when audioop-lts is installed.
# ============================================================

CONFIG_FILE = str(Path(__file__).resolve().parent / "ticket_config.json")

FOOTER_TEXT = "Greenville Roleplay Genesis"
TRANSCRIPT_CHANNEL_ID = 1536228921891225600  # ticket-transcripts

MAIN_PANEL_TEXT = (
    "Welcome to GVRG | Support Channel. Below you can find differnet type of supports you might need.\n\n"
    "- General Support\n"
    "  - Have any questions? Ask here!\n"
    "- Civilian Report\n"
    "  - Report a civilian within GVRG.\n"
    "- Staff Report\n"
    "  - Report a staff member within GVRG\n"
    "- Partnership\n"
    "  - Request a partnership with GVRG"
)

PANEL_CATEGORIES = {
    "general-support": {
        "name": "General Support",
        "description": "Have any questions? Ask here!",
    },
    "civilian-report": {
        "name": "Civilian Report",
        "description": "Report a civilian within GVRG.",
    },
    "staff-report": {
        "name": "Staff Report",
        "description": "Report a staff member within GVRG",
    },
    "partnership": {
        "name": "Partnership",
        "description": "Request a partnership with GVRG",
    },
    "moderation-appeal": {
        "name": "Moderation Appeal",
        "description": "Appeal a warning, infraction, or other moderation action.",
    },
}

# ---------- CONFIG STORAGE ----------

DEFAULT_CONFIG = {
    "guilds": {}
}


def load_config():
    """Load and repair the ticket configuration file."""
    default = {"guilds": {}}

    if not os.path.exists(CONFIG_FILE):
        return default

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError, TypeError):
        return default

    if not isinstance(config, dict):
        config = {}
    if not isinstance(config.get("guilds"), dict):
        config["guilds"] = {}

    changed = False
    defaults = {
        "staff_roles": [],
        "log_channel_id": None,
        "transcript_channel_id": None,
        "ticket_counter": 0,
        "categories": {},
        "panels": {},
        "tickets": {}
    }

    for gid, guild_data in list(config["guilds"].items()):
        if not isinstance(guild_data, dict):
            config["guilds"][gid] = {}
            guild_data = config["guilds"][gid]
            changed = True
        for key, value in defaults.items():
            if key not in guild_data:
                guild_data[key] = value.copy() if isinstance(value, (dict, list)) else value
                changed = True
        if not isinstance(guild_data["staff_roles"], list):
            guild_data["staff_roles"] = []
            changed = True
        if not isinstance(guild_data["categories"], dict):
            guild_data["categories"] = {}
            changed = True
        if not isinstance(guild_data["panels"], dict):
            guild_data["panels"] = {}
            changed = True

        # Migrate the old transcript destination to the channel confirmed by the latest server audit.
        if guild_data.get("transcript_channel_id") == 1552446601170255995:
            guild_data["transcript_channel_id"] = TRANSCRIPT_CHANNEL_ID
            changed = True

    if changed:
        save_config(config)
    return config


def save_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)


def guild_config(guild_id):
    config = load_config()
    gid = str(guild_id)

    if gid not in config["guilds"] or not isinstance(config["guilds"][gid], dict):
        config["guilds"][gid] = {
            "staff_roles": [],
            "log_channel_id": None,
            "transcript_channel_id": None,
            "ticket_counter": 0,
            "categories": {},
            "panels": {},
            "tickets": {}
        }
        save_config(config)

    guild_data = config["guilds"][gid]
    guild_data.setdefault("staff_roles", [])
    guild_data.setdefault("log_channel_id", None)
    guild_data.setdefault("transcript_channel_id", None)
    guild_data.setdefault("ticket_counter", 0)
    guild_data.setdefault("categories", {})
    guild_data.setdefault("panels", {})
    guild_data.setdefault("tickets", {})

    return config, guild_data


def next_ticket_number(guild_id):
    config, guild = guild_config(guild_id)
    guild["ticket_counter"] = int(guild.get("ticket_counter", 0)) + 1
    save_config(config)
    return guild["ticket_counter"]


def get_ticket_data(channel):
    """Return ticket data from the bot config instead of exposing it in the channel topic.

    Older tickets that still have the legacy TICKET_DATA topic are read for
    backwards compatibility and migrated into the config on first access.
    """
    if not channel or not getattr(channel, "guild", None):
        return None

    config = load_config()
    guild_data = config.get("guilds", {}).get(str(channel.guild.id))
    if not isinstance(guild_data, dict):
        return None

    tickets = guild_data.setdefault("tickets", {})
    data = tickets.get(str(channel.id))
    if isinstance(data, dict):
        return data

    # Backwards compatibility for tickets created by older versions.
    topic = getattr(channel, "topic", None) or ""
    prefix = "TICKET_DATA:"
    if topic.startswith(prefix):
        try:
            data = json.loads(topic[len(prefix):])
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        tickets[str(channel.id)] = data
        save_config(config)
        return data

    return None


async def update_ticket_data(channel, data):
    """Persist ticket data without putting internal JSON into the channel topic."""
    config = load_config()
    guild_id = str(channel.guild.id)
    guild_data = config.setdefault("guilds", {}).setdefault(guild_id, {})
    guild_data.setdefault("tickets", {})[str(channel.id)] = data
    save_config(config)

    # Keep the topic empty/clean. The ticket state is internal bot data and
    # should never be shown to people in the Discord channel header.
    try:
        if channel.topic:
            await channel.edit(topic="")
    except discord.HTTPException:
        pass


def is_staff(member, guild_data):
    if not isinstance(member, discord.Member):
        return False

    if member.guild_permissions.administrator:
        return True

    staff_roles = {int(x) for x in guild_data.get("staff_roles", [])}
    return any(role.id in staff_roles for role in member.roles)


def get_support_role_ids(guild_data, category_key=None):
    """Return all configured support role IDs, with backwards compatibility."""
    if category_key:
        category = guild_data.get("categories", {}).get(category_key, {})
        if isinstance(category, dict):
            raw_ids = category.get("support_role_ids")
            if raw_ids is None and category.get("support_role_id"):
                raw_ids = [category.get("support_role_id")]
            if raw_ids:
                result = set()
                for value in raw_ids:
                    try:
                        result.add(int(value))
                    except (TypeError, ValueError):
                        continue
                return result

    result = set()
    for value in guild_data.get("staff_roles", []):
        try:
            result.add(int(value))
        except (TypeError, ValueError):
            continue
    return result


def get_support_role_id(guild_data, category_key=None):
    """Legacy helper returning one role ID where older code expects it."""
    role_ids = get_support_role_ids(guild_data, category_key)
    return next(iter(role_ids), None)


def has_support_role(member, guild_data, category_key=None):
    """Return True when the member has any configured support role for this ticket."""
    if not isinstance(member, discord.Member):
        return False
    role_ids = get_support_role_ids(guild_data, category_key)
    role_ids.discard(ROLE_VERIFIED_MEMBER)
    return any(role.id in role_ids for role in member.roles)


def is_admin(member):
    return isinstance(member, discord.Member) and member.guild_permissions.administrator


def ticket_number(data):
    return int(data.get("number", 0))


# ---------- TRANSCRIPTS ----------

async def build_transcript(channel):
    """Build a Discord-style HTML transcript with py-discord-html-transcripts."""
    transcript = await chat_exporter.export(
        channel,
        bot=bot,
        guild=channel.guild,
        tz_info="America/Chicago",
        military_time=False,
        fancy_times=True,
    )

    if transcript is None:
        raise RuntimeError("The transcript exporter returned no transcript.")

    return transcript.encode("utf-8")


# ---------- TICKET CREATION ----------

async def create_ticket(interaction, category_key):
    guild = interaction.guild

    if guild is None:
        await interaction.response.send_message(
            "This can only be used inside a server.",
            ephemeral=True
        )
        return

    # Defer the panel interaction immediately so the final ticket confirmation
    # can safely be sent as an ephemeral follow-up after the ticket is created.
    await interaction.response.defer(ephemeral=True)

    config, gdata = guild_config(guild.id)
    category_config = gdata.get("categories", {}).get(category_key)

    if not category_config:
        await interaction.followup.send(
            "That ticket category is no longer configured.",
            ephemeral=True
        )
        return

    category = guild.get_channel(int(category_config["category_id"]))

    if not isinstance(category, discord.CategoryChannel):
        await interaction.followup.send(
            "The configured ticket category could not be found.",
            ephemeral=True
        )
        return

    # Each ticket category can have one or more support roles.
    support_role_ids = get_support_role_ids(gdata, category_key)
    staff_roles = []
    for role_id in support_role_ids:
        role = guild.get_role(int(role_id))
        if role:
            staff_roles.append(role)

    # Allow up to 2 open tickets per user for EACH ticket category.
    # Example: a user can have 2 General Support + 2 Civilian Report +
    # 2 Staff Report + 2 Partnership tickets open at the same time.
    open_ticket_count = 0
    for channel in category.text_channels:
        ticket_data = get_ticket_data(channel)
        if not ticket_data:
            continue
        if (
            int(ticket_data.get("creator_id", 0)) == interaction.user.id
            and ticket_data.get("category_key") == category_key
            and ticket_data.get("status") == "open"
        ):
            open_ticket_count += 1

    if open_ticket_count >= 2:
        await interaction.followup.send(
            "You already have 2 open tickets for this support type. Please close one before opening another.",
            ephemeral=True,
        )
        return

    number = next_ticket_number(guild.id)
    padded = f"{number:04d}"

    # next_ticket_number() saves the incremented counter to disk. Reload the
    # guild configuration here so the later ticket save cannot overwrite the
    # incremented counter with stale data.
    config, gdata = guild_config(guild.id)

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(
            view_channel=False
        ),
        interaction.user: discord.PermissionOverwrite(
            view_channel=True,
            send_messages=True,
            read_message_history=True,
            attach_files=True,
            embed_links=True
        ),
    }

    for role in staff_roles:
        overwrites[role] = discord.PermissionOverwrite(
            view_channel=True,
            send_messages=True,
            read_message_history=True,
            attach_files=True,
            embed_links=True
        )

    if guild.me:
        overwrites[guild.me] = discord.PermissionOverwrite(
            view_channel=True,
            send_messages=True,
            read_message_history=True,
            manage_channels=True,
            manage_messages=True
        )

    data = {
        "number": number,
        "creator_id": interaction.user.id,
        "creator_name": str(interaction.user),
        "category_key": category_key,
        "status": "open",
        "priority": "Normal",
        "claimed_by": None,
        "private": False,
        "created_at": central_now().isoformat()
    }

    channel = await guild.create_text_channel(
        name=f"ticket-{padded}",
        category=category,
        overwrites=overwrites,
        topic="",
        reason=f"Ticket #{number} created by {interaction.user}"
    )

    # Ticket state is kept in ticket_config.json, never in the public channel topic.
    config["guilds"][str(guild.id)].setdefault("tickets", {})[str(channel.id)] = data
    save_config(config)

    # Send the creation confirmation as an ephemeral interaction message.
    # It appears only to the user who opened the ticket and links the new channel.
    await interaction.followup.send(
        f"Ticket created: {channel.mention}",
        ephemeral=True,
    )

    # Ticket welcome message. There is intentionally NO close button; closing is
    # done with the -close prefix command. The format section is shown as a
    # Discord code block to match the requested Ticket Tool-style appearance.
    ticket_embed_text = {
        "general-support": (
            "Support will be with you shortly. In the mean time follow the format:\n\n"
            "```\n"
            "Username:\n"
            "Question/Concerns:\n"
            "Evidence: (If needed)\n"
            "```\n\n"
            "-# Support Staff: `-close` to close the ticket."
        ),
        "civilian-report": (
            "Support will be with you shortly. In the mean time follow the format:\n\n"
            "```\n"
            "Username:\n"
            "Civilian Reporting: (Roblox username)\n"
            "Reason:\n"
            "Evidence: (Needed)\n"
            "```\n\n"
            "-# Support Staff: `-close` to close the ticket."
        ),
        "staff-report": (
            "Support will be with you shortly. In the mean time follow the format:\n\n"
            "```\n"
            "Username:\n"
            "Staff Member Reporting: (Roblox username)\n"
            "Reason:\n"
            "Evidence: (Needed)\n"
            "```\n\n"
            "-# Support Staff: `-close` to close the ticket."
        ),
        "partnership": (
            "Support will be with you shortly. In the meantime, please complete the format below:\n\n"
            "```\n"
            "Username:\n"
            "Server Name:\n"
            "Server Members:\n"
            "Server Ad:\n"
            "```\n\n"
            "-# Support Staff: `-close` to close the ticket."
        ),
        "moderation-appeal": (
            "Support will be with you shortly. In the meantime, please complete the format below:\n\n"
            "```\n"
            "Username:\n"
            "Moderation Action Being Appealed: (Warning, infraction, etc.)\n"
            "Reason for Appeal: (Explain why this action should be removed)\n"
            "```\n\n"
            "-# Support Staff: `-close` to close the ticket."
        ),
    }

    embed = discord.Embed(
        description=ticket_embed_text.get(
            category_key,
            "Support will be with you shortly."
        ),
        color=discord.Color.from_str("#596744"),
    )
    embed.set_footer(text=FOOTER_TEXT)

    await channel.send(
        content=f"Welcome {interaction.user.mention}",
        embed=embed,
    )



# ---------- PANEL VIEW ----------

class TicketPanelView(discord.ui.LayoutView):
    """The GVRG panel is a true Discord Components V2 LayoutView.

    There is intentionally no discord.Embed used anywhere in this panel.
    The visible card is produced by a V2 Container with TextDisplay,
    Separator, and ActionRow components, matching Discord's V2 layout style.
    """

    def __init__(self, guild_id, panel_id, categories, category_keys=None):
        super().__init__(timeout=None)
        # Restore the dedicated panel scope from its saved panel ID as well as
        # from an explicit argument. This keeps the appeal panel dedicated after
        # a dropdown reset or bot restart instead of falling back to Support Tickets.
        if category_keys is None and str(panel_id) == "moderation-appeal":
            category_keys = ["moderation-appeal"]
        self.category_keys = category_keys

        # One V2 Container is the card itself.
        # Leave accent_color unset. This is important: a colored accent bar makes
        # the component look like an embed, while the reference V2 card has no
        # colored embed-style left border.
        container = discord.ui.Container()

        # Large V2 heading, like Discord's Components V2 examples.
        is_appeal_panel = category_keys == ["moderation-appeal"]
        container.add_item(discord.ui.TextDisplay(
            "# GVRG | Moderation Appeal" if is_appeal_panel else "# GVRG | Support Tickets"
        ))

        # Body text is another V2 TextDisplay component.
        panel_text = (
            "Use this panel to appeal a moderation action, such as a warning or infraction. "
            "Select **Moderation Appeal** below to open a private ticket."
            if is_appeal_panel else MAIN_PANEL_TEXT
        )
        container.add_item(discord.ui.TextDisplay(panel_text))

        # V2 divider.
        container.add_item(discord.ui.Separator())

        # The select menu is placed inside a V2 ActionRow.
        action_row = discord.ui.ActionRow()
        action_row.add_item(
            TicketPanelSelect(guild_id, panel_id, categories, category_keys=category_keys)
        )
        container.add_item(action_row)

        # Footer/subtext is also a V2 TextDisplay, not an embed footer.
        container.add_item(discord.ui.Separator())
        container.add_item(discord.ui.TextDisplay(f"-# {FOOTER_TEXT}"))

        # The LayoutView contains only V2 components.
        self.add_item(container)


class TicketPanelSelect(discord.ui.Select):
    def __init__(self, guild_id, panel_id, categories, category_keys=None):
        options = []

        # Keep the visible panel options exactly aligned with the requested
        # support types. They are only offered once the matching category has
        # been configured with a Discord category channel ID.
        visible_keys = category_keys if category_keys is not None else list(PANEL_CATEGORIES)
        for key in visible_keys:
            definition = PANEL_CATEGORIES.get(key)
            if definition is None:
                continue
            data = categories.get(key)
            if not isinstance(data, dict) or not data.get("category_id"):
                continue

            options.append(
                discord.SelectOption(
                    label=definition["name"],
                    value=key,
                    description=definition["description"][:100],
                )
            )

        if not options:
            options = [
                discord.SelectOption(
                    label="No categories configured",
                    value="none",
                    description="Configure the ticket category first.",
                )
            ]

        super().__init__(
            placeholder="Select a support type...",
            min_values=1,
            max_values=1,
            options=options,
            custom_id=f"ticket_panel:{guild_id}:{panel_id}",
        )

        self.guild_id = guild_id
        self.panel_id = panel_id
        self.category_keys = category_keys

    async def callback(self, interaction: discord.Interaction):
        value = self.values[0]

        if value == "none":
            await interaction.response.send_message(
                "This panel has no configured ticket categories.",
                ephemeral=True,
            )
            await self.reset_panel_dropdown(interaction)
            return

        # Create the ticket, then re-render the original panel with a fresh
        # select component so the user's selected option clears immediately.
        await create_ticket(interaction, value)
        await self.reset_panel_dropdown(interaction)

    async def reset_panel_dropdown(self, interaction: discord.Interaction):
        if not interaction.message or not interaction.guild:
            return
        try:
            _, guild_data = guild_config(interaction.guild.id)
            await interaction.message.edit(
                view=TicketPanelView(
                    str(interaction.guild.id),
                    str(self.panel_id),
                    guild_data.get("categories", {}),
                    category_keys=self.category_keys,
                )
            )
        except (discord.HTTPException, TypeError, ValueError) as exc:
            print(f"Ticket panel dropdown reset failed: {exc!r}")


# ---------- CLOSED TICKET CONTROLS ----------

class TicketClosedView(discord.ui.View):
    """Support controls shown after -close."""

    def __init__(self):
        super().__init__(timeout=None)
        # Non-clickable header styled like a Discord button.
        header = discord.ui.Button(
            label="Transcript --> Delete",
            style=discord.ButtonStyle.secondary,
            disabled=True,
            custom_id="ticket:closed_header",
            row=0,
        )
        self.add_item(header)

    @discord.ui.button(
        label="Transcript",
        style=discord.ButtonStyle.secondary,
        custom_id="ticket:closed_transcript",
        row=1,
    )
    async def transcript_button(self, interaction, button):
        data = get_ticket_data(interaction.channel)

        if not data:
            await interaction.response.send_message(
                "This is not a recognized ticket.",
                ephemeral=True,
            )
            return

        _, gdata = guild_config(interaction.guild.id)

        if not has_support_role(interaction.user, gdata, data.get("category_key")):
            await interaction.response.defer(ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        _, ticket_gdata = guild_config(interaction.guild.id)
        transcript_channel_id = ticket_gdata.get("transcript_channel_id") or TRANSCRIPT_CHANNEL_ID

        try:
            delivered = await send_transcript_to_log_channel(interaction.channel, data)

            if delivered:
                embed = discord.Embed(
                    description=f"Transcript saved: <#{int(transcript_channel_id)}>",
                    color=discord.Color.from_str("#596744"),
                )
                embed.set_footer(text=FOOTER_TEXT)
                await interaction.followup.send(embed=embed, ephemeral=True)
            else:
                embed = discord.Embed(
                    title="Transcript Not Sent",
                    description="The transcript could not be sent to the transcript channel.",
                    color=discord.Color.from_str("#7BCB4A"),
                )
                embed.set_footer(text=FOOTER_TEXT)
                await interaction.followup.send(embed=embed, ephemeral=True)
                print(
                    f"Transcript could not be delivered for ticket #{ticket_number(data)}"
                )
        except (discord.HTTPException, OSError, ValueError) as exc:
            print(f"Transcript error: {exc!r}")
            embed = discord.Embed(
                title="Transcript Not Sent",
                description="An error occurred while sending the transcript.",
                color=discord.Color.from_str("#7BCB4A"),
            )
            embed.set_footer(text=FOOTER_TEXT)
            try:
                await interaction.followup.send(embed=embed, ephemeral=True)
            except discord.HTTPException:
                pass


    @discord.ui.button(
        label="Open",
        style=discord.ButtonStyle.success,
        custom_id="ticket:closed_open",
        row=1,
    )
    async def open_button(self, interaction, button):
        data = get_ticket_data(interaction.channel)

        if not data:
            await interaction.response.send_message(
                "This ticket is no longer valid.",
                ephemeral=True,
            )
            return

        _, gdata = guild_config(interaction.guild.id)
        if not has_support_role(interaction.user, gdata, data.get("category_key")):
            await interaction.response.send_message(
                "Only the configured support role can use these buttons.",
                ephemeral=True,
            )
            return

        if data.get("status") == "open":
            await interaction.response.send_message(
                "This ticket is already open.",
                ephemeral=True,
            )
            return

        await reopen_ticket(interaction, data)

    @discord.ui.button(
        label="Delete",
        style=discord.ButtonStyle.danger,
        custom_id="ticket:closed_delete",
        row=1,
    )
    async def delete_button(self, interaction, button):
        data = get_ticket_data(interaction.channel)

        if not data:
            await interaction.response.send_message(
                "This ticket is no longer valid.",
                ephemeral=True,
            )
            return

        _, gdata = guild_config(interaction.guild.id)
        if not has_support_role(interaction.user, gdata, data.get("category_key")):
            await interaction.response.send_message(
                "Only the configured support role can use these buttons.",
                ephemeral=True,
            )
            return

        # Acknowledge the button interaction before deleting the channel.
        # This prevents an "Interaction Failed" state while the API request
        # is being processed.
        await interaction.response.defer(ephemeral=True)

        deleted = await permanently_delete_ticket(
            interaction.channel,
            data,
            interaction.user,
        )

        if not deleted:
            try:
                await interaction.followup.send(
                    "The ticket could not be deleted. Please try again.",
                    ephemeral=True,
                )
            except discord.HTTPException:
                pass


# ---------- TICKET LIFECYCLE ----------



async def send_transcript_to_log_channel(channel, data):
    """Send the current ticket transcript to the configured transcript channel."""
    guild = channel.guild
    _, gdata = guild_config(guild.id)

    channel_id = gdata.get("transcript_channel_id") or TRANSCRIPT_CHANNEL_ID
    try:
        channel_id = int(channel_id)
    except (TypeError, ValueError):
        channel_id = TRANSCRIPT_CHANNEL_ID

    destination = guild.get_channel(channel_id)

    if not isinstance(destination, discord.TextChannel):
        print(f"Transcript channel {channel_id} was not found or is not a text channel.")
        return False

    try:
        content = await build_transcript(channel)
        filename = f"ticket-{ticket_number(data)}-transcript.html"
        file = discord.File(io.BytesIO(content), filename=filename)
        number = ticket_number(data)
        summary = (
            f"**Ticket #{number} Transcript**\n"
            f"Ticket: `ticket-{number:04d}`\n"
            f"Closed by: <@{data.get('closed_by', 0)}>"
        )
        # Publish to the transcript website first. On success, post only a link that opens
        # this ticket on the site; otherwise fall back to attaching the HTML file.
        link = None
        if site_publisher:
            try:
                link = await asyncio.wait_for(
                    asyncio.shield(site_publisher.publish_ticket(channel, data, content)),
                    timeout=45,
                )
            except asyncio.TimeoutError:
                print(f"[transcript-site] upload for ticket #{number} is taking too long; attaching the file instead.")
        if link:
            owner_id = data.get("creator_id")
            owner_label = f"<@{owner_id}>" if owner_id else "Unknown"
            category_label = str(data.get("category_key") or "General Support").replace("-", " ").replace("_", " ").title()
            panel_name = str(data.get("panel_name") or data.get("panel_id") or category_label).replace("-", " ").replace("_", " ").title()
            closed_by_id = data.get("closed_by")
            closed_by_label = f"<@{closed_by_id}>" if closed_by_id else "Unknown"
            heading = f"{category_label} Transcript"

            # Ticket Tool-inspired layout: ticket metadata, owner avatar, direct link,
            # and a numbered list of users who can view the ticket.
            owner = guild.get_member(int(owner_id)) if owner_id else None
            avatar_url = str(owner.display_avatar.url) if owner else str(guild.icon.url) if guild.icon else "https://cdn.discordapp.com/embed/avatars/0.png"
            # Include only non-bot users who actually sent a message in this ticket.
            # Channel.members includes everyone with access, even if they never chatted.
            chatted_users = []
            chatted_user_ids = set()
            async for message in channel.history(limit=None, oldest_first=True):
                member = message.author
                if member.bot or member.id in chatted_user_ids:
                    continue
                chatted_user_ids.add(member.id)
                chatted_users.append(member)
            user_lines = [f"**{index}.** {member.mention}" for index, member in enumerate(chatted_users[:10], 1)]
            if len(chatted_users) > 10:
                user_lines.append(f"*and {len(chatted_users) - 10} more user(s)*")
            if not user_lines:
                user_lines = [f"**1.** {owner_label}"]

            details_text = (
                f"**Ticket Owner:** {owner_label}　　 **Ticket Name:** `{channel.name}`\n"
                f"**Panel Name:** {panel_name}\n"
                f"**Type of Support:** {category_label}\n"
                f"-# Closed by {closed_by_label} · Ticket #{number}"
            )
            participant_text = "**Users in Ticket:**\n" + "\n".join(user_lines)
            components = [{
                "type": 17,
                "components": [
                    {"type": 10, "content": f"## {heading}"},
                    {"type": 14, "spacing": 1},
                    {
                        "type": 9,
                        "components": [{"type": 10, "content": details_text}],
                        "accessory": {
                            "type": 11,
                            "media": {"url": avatar_url},
                            "description": "Ticket owner's profile picture",
                        },
                    },
                    {"type": 14, "spacing": 1},
                    {"type": 10, "content": participant_text},
                    {"type": 14, "spacing": 1},
                    {
                        "type": 1,
                        "components": [{
                            "type": 2,
                            "style": 5,
                            "label": "Direct Transcript",
                            "url": link,
                        }],
                    },
                ],
            }]
            await bot.http.request(
                discord.http.Route("POST", "/channels/{channel_id}/messages", channel_id=destination.id),
                json={"components": components, "flags": 32768}
            )
        else:
            summary += "\\n*The website upload failed. Check the transcript website configuration.*"
            await destination.send(content=summary)
        # Keep the V2 notice at the bottom, below the transcript just posted.
        try:
            await refresh_transcript_notice(destination)
        except Exception as exc:
            print(f"Transcript notice refresh failed: {exc!r}")
        return True
    except (discord.HTTPException, OSError, ValueError) as exc:
        print(f"Transcript delivery error for #{ticket_number(data)}: {exc!r}")
        return False


async def close_ticket(channel, data, closed_by):
    guild = channel.guild

    data["status"] = "closed"
    data["closed_by"] = closed_by.id
    data["closed_at"] = central_now().isoformat()

    await update_ticket_data(channel, data)

    # Creator can still view the ticket, but cannot send while it is closed.
    creator = guild.get_member(int(data["creator_id"]))
    if creator:
        await channel.set_permissions(
            creator,
            view_channel=True,
            send_messages=False,
            read_message_history=True,
        )

    embed = discord.Embed(
        description=f"Ticket Closed by {closed_by.mention}",
        color=discord.Color.from_str("#7BCB4A"),
    )
    embed.set_footer(text=FOOTER_TEXT)

    # First message: the closure notice.
    await channel.send(embed=embed)

    # The closed-ticket view contains a non-clickable GVRG Ticket Controls
    # header button followed by the actual support controls.
    await channel.send(view=TicketClosedView())

    # Transcripts are NOT automatically sent when the ticket is closed.
    # Support staff can save one with the Transcript button below.


async def reopen_ticket(interaction, data):
    channel = interaction.channel
    guild = interaction.guild

    data["status"] = "open"
    data.pop("closed_by", None)
    data.pop("closed_at", None)

    await update_ticket_data(channel, data)

    creator = guild.get_member(int(data["creator_id"]))
    if creator:
        await channel.set_permissions(
            creator,
            view_channel=True,
            send_messages=True,
            read_message_history=True,
            attach_files=True,
            embed_links=True,
        )

    await interaction.response.send_message(
        f"Ticket #{ticket_number(data)} is now open."
    )


async def permanently_delete_ticket(channel, data, deleted_by=None):
    """Delete a ticket channel with retry handling for transient Discord/network errors."""
    reason = (
        f"Ticket #{ticket_number(data)} deleted"
        + (f" by {deleted_by}" if deleted_by else "")
    )

    # Try the delete a few times because Discord connectivity can briefly drop.
    # Do not remove the ticket metadata until the channel deletion succeeds.
    for attempt in range(3):
        try:
            await channel.delete(reason=reason)

            config = load_config()
            guild_data = config.get("guilds", {}).get(str(channel.guild.id))
            if isinstance(guild_data, dict):
                guild_data.setdefault("tickets", {}).pop(str(channel.id), None)
                save_config(config)

            return True

        except discord.NotFound:
            # Discord already deleted the channel, so treat that as success.
            config = load_config()
            guild_data = config.get("guilds", {}).get(str(channel.guild.id))
            if isinstance(guild_data, dict):
                guild_data.setdefault("tickets", {}).pop(str(channel.id), None)
                save_config(config)

            return True

        except discord.Forbidden:
            print(
                f"Ticket delete forbidden for #{ticket_number(data)}. "
                "Make sure the bot has Manage Channels."
            )
            return False

        except (discord.HTTPException, aiohttp.ClientError, asyncio.TimeoutError) as exc:
            print(
                f"Ticket delete attempt {attempt + 1}/3 failed for "
                f"#{ticket_number(data)}: {exc!r}"
            )
            if attempt < 2:
                await asyncio.sleep(1.5 * (attempt + 1))

    return False


# ---------- PREFIX COMMANDS ----------

# --- BOT CLASS ---
class ModBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="-", intents=intents)

    def load_runtime_components(self):
        """Register context menus and persistent views.

        Called once at startup (from setup_hook) and again by -reload, so a hot
        reload re-binds them to the freshly loaded code.
        """
        self.tree.add_command(edit_caselog_menu)
        self.tree.add_command(delete_caselog_menu)
        self.tree.add_command(edit_say_message_menu)
        # Giveaway reroll (right-click a giveaway message -> Apps -> Reroll Giveaway).
        self.tree.add_command(reroll_giveaway_menu)
        self.tree.add_command(change_ea_code_context_menu)

        # Persistent GVRG ticket controls and the permanent GVRG Hub dropdown.
        self.add_view(TicketClosedView())
        self.add_view(GVRGHubView())
        self.add_view(StaffHubView())
        # Persistent giveaway "Enter" button (works on every giveaway message,
        # including ones posted before a restart).
        self.add_view(GiveawayView())
        # One persistent view per startup (custom_ids are per startup, not per guild), so panels
        # keep working after a restart in every server without reading the data file.
        for _system_id in EA_SYSTEMS:
            try:
                self.add_view(EarlyAccessPanelView(0, _system_id, data=_new_ea_system_data()))
            except Exception as exc:
                print(f"[Early Access] Could not register persistent panel view for {_system_id}: {exc!r}")
        # Persistent Accept/Deny buttons on staff resignation requests (the member ID is in the button's custom_id).
        self.add_dynamic_items(ResignAcceptButton, ResignDenyButton, StaffAppealButton, StaffAppealAcceptButton, StaffAppealDenyButton)

        # Staff of the Month polls: re-bind every saved poll so its dropdowns keep working after a restart.
        try:
            for _msg_id, _poll in load_sotm_data()["polls"].items():
                if _poll.get("candidates") and _poll.get("status") != "deleted":
                    self.add_view(SotmView(_poll), message_id=int(_msg_id))
        except Exception as exc:
            print(f"SOTM: could not re-register polls: {exc!r}")

        # Re-register configured Components V2 ticket panels after restart.
        config = load_config()
        for guild_id, guild_data in config.get("guilds", {}).items():
            for panel_id, panel in guild_data.get("panels", {}).items():
                if not panel.get("active", True):
                    continue
                message_id = panel.get("message_id")
                if not message_id:
                    continue
                try:
                    self.add_view(
                        TicketPanelView(
                            str(guild_id),
                            str(panel_id),
                            guild_data.get("categories", {}),
                        ),
                        message_id=int(message_id),
                    )
                except (TypeError, ValueError, discord.HTTPException):
                    pass

    async def setup_hook(self):
        self.load_runtime_components()
        await self.tree.sync()

bot = ModBot()


# ---------- GVRG SERVER AUDIT + ROLE PERMISSION SYNC ----------
def _audit_configured_ids():
    """Return statically configured role/channel IDs without exposing secrets."""
    refs = {"roles": {}, "channels": {}}
    for name, value in globals().copy().items():
        if name.startswith("ROLE_") and isinstance(value, int) and not isinstance(value, bool):
            refs["roles"].setdefault(value, []).append(name)
        elif (name.endswith("_ROLE_ID") or name.endswith("_ROLE") or name.endswith("_PING_ROLE")) and isinstance(value, int) and not isinstance(value, bool):
            refs["roles"].setdefault(value, []).append(name)
        elif name.endswith("_CHANNEL_ID") and isinstance(value, int) and not isinstance(value, bool):
            refs["channels"].setdefault(value, []).append(name)
    for name, value in globals().copy().items():
        if name.endswith("_ROLES") and isinstance(value, (list, tuple, set)):
            for role_id in value:
                if isinstance(role_id, int):
                    refs["roles"].setdefault(role_id, []).append(name)
    return refs


@bot.command(name="audit")
@commands.guild_only()
@commands.has_permissions(administrator=True)
async def audit_server(ctx: commands.Context):
    """Create a read-only report of server roles, channels, and configured IDs."""
    guild = ctx.guild
    refs = _audit_configured_ids()
    lines = [
        f"GVRG SERVER AUDIT — {guild.name}",
        f"Guild ID: {guild.id}",
        f"Generated: {central_now().strftime('%Y-%m-%d %I:%M:%S %p %Z')}",
        "",
        "SUMMARY",
        f"Roles: {len(guild.roles)}",
        f"Categories: {sum(isinstance(c, discord.CategoryChannel) for c in guild.channels)}",
        f"Channels (including categories): {len(guild.channels)}",
        "",
        "BOT PERMISSIONS / CHANNEL ACCESS",
    ]
    me = guild.me
    if me:
        guild_perms = me.guild_permissions
        lines.append("Guild-level: " + ", ".join(
            f"{name}={'YES' if getattr(guild_perms, name, False) else 'NO'}"
            for name in ("administrator", "manage_channels", "manage_roles", "view_audit_log")
        ))
    for channel in sorted(guild.channels, key=lambda c: (getattr(c, "position", 0), c.name.lower())):
        if me:
            perms = channel.permissions_for(me)
            needed = ["view_channel"]
            if isinstance(channel, (discord.TextChannel, discord.ForumChannel, discord.Thread)):
                needed.extend(["send_messages", "read_message_history"])
            elif isinstance(channel, (discord.VoiceChannel, discord.StageChannel)):
                needed.append("connect")
            missing = [x for x in needed if hasattr(perms, x) and not getattr(perms, x)]
            status = "OK" if not missing else "MISSING: " + ", ".join(missing)
        else:
            status = "Bot member not available in cache"
        kind = "CATEGORY" if isinstance(channel, discord.CategoryChannel) else type(channel).__name__.replace("Channel", "").upper()
        lines.append(f"[{kind}] {channel.name} | ID {channel.id} | {status}")

    lines.extend(["", "ROLES"])
    for role in sorted(guild.roles, key=lambda r: r.position, reverse=True):
        lines.append(
            f"{role.name} | ID {role.id} | position={role.position} | "
            f"managed={role.managed} | members={len(role.members)}"
        )

    lines.extend(["", "HARDCODED ROLE REFERENCES"])
    for role_id, names in sorted(refs["roles"].items()):
        role = guild.get_role(role_id)
        lines.append(f"{'FOUND' if role else 'MISSING'} | ID {role_id} | names={', '.join(sorted(set(names)))}"
                     + (f" | server name={role.name}" if role else ""))

    lines.extend(["", "HARDCODED CHANNEL REFERENCES"])
    for channel_id, names in sorted(refs["channels"].items()):
        channel = guild.get_channel(channel_id)
        lines.append(f"{'FOUND' if channel else 'MISSING'} | ID {channel_id} | names={', '.join(sorted(set(names)))}"
                     + (f" | server name={channel.name}" if channel else ""))

    # Check IDs in the ticket configuration without printing secrets or file contents.
    try:
        config = load_config()
        lines.extend(["", "TICKET CONFIGURATION CHECK"])
        guild_data = config.get("guilds", {}).get(str(guild.id), {})
        if not guild_data:
            lines.append("No ticket configuration found for this server in the bot's local config.")
        else:
            lines.append(f"Configured ticket categories: {len(guild_data.get('categories', {}))}")
            lines.append(f"Configured ticket panels: {len(guild_data.get('panels', {}))}")
            for category_name, data in guild_data.get("categories", {}).items():
                for key, value in data.items():
                    if isinstance(value, int) and ("role" in key.lower() or "channel" in key.lower()):
                        obj = guild.get_role(value) if "role" in key.lower() else guild.get_channel(value)
                        lines.append(f"{category_name}.{key}: {'FOUND' if obj else 'MISSING'} ID {value}")
    except Exception as exc:
        lines.extend(["", f"Ticket config check could not be completed: {type(exc).__name__}"])

    lines.extend([
        "", "NOTES",
        "This report is read-only. It does not change roles, channels, permissions, or configuration.",
        "IDs marked MISSING may be outdated, belong to another server, or no longer exist.",
    ])
    report = "\n".join(lines)
    file = discord.File(io.BytesIO(report.encode("utf-8")), filename=f"gvrg-audit-{guild.id}.txt")
    await ctx.reply(
        f"Audit complete for **{guild.name}**. This was a read-only check. "
        "Download the report to review channel access, role IDs, and configured references.",
        file=file,
        mention_author=False,
    )


# ---------- GVRG TICKET COMMANDS ----------

# ---------- PREFIX COMMANDS ----------

@bot.command(name="close")
@commands.guild_only()
async def close_prefix(ctx: commands.Context):
    """Close the current ticket with -close and show support controls."""
    try:
        await ctx.message.delete()
    except discord.HTTPException:
        pass

    data = get_ticket_data(ctx.channel)

    if not data:
        await ctx.send(
            "This command can only be used inside a ticket.",
            delete_after=5,
        )
        return

    _, gdata = guild_config(ctx.guild.id)

    # Only the configured support role for this ticket category may close it.
    # The verified-member role is explicitly not a support role.
    if not has_support_role(ctx.author, gdata, data.get("category_key")):
        await ctx.send(
            "Only the ticket's support team can close this ticket.",
            delete_after=5,
        )
        return

    if data.get("status") != "open":
        await ctx.send(
            "This ticket is already closed.",
            delete_after=5,
        )
        return

    await close_ticket(ctx.channel, data, ctx.author)



# ---------- GVRG HUB INFORMATION PANEL (COMPONENTS V2) ----------

HUB_ROLEPLAY_INFO = """# Roleplay Information
Please read these guidelines to understand the server's rules and expectations.

## Peacetime Alert Levels
Roleplay rules depend on the Peacetime Alert Level. Each level defines speed limits, allowed crimes, and expected behavior.

- **Peacetime Strict Alert**
  - FRP speed limit: 70 mph.
  - No crimes are allowed, including vehicle theft, robberies, or assaults.
  - Follow all laws and roleplay realistically.
  - Do not chase or attack others without a scripted scenario.
  - Obey traffic signals and speed limits.
- **Peacetime Regular Alert**
  - FRP speed limit: 80 mph.
  - Very minor crimes may be allowed, such as minor traffic violations, jaywalking, or small shoplifting.
  - Keep roleplay realistic.
  - Minor theft or speeding to avoid an accident may occur only within a realistic scenario.
- **No Peacetime Alert**
  - FRP speed limit: 95 mph.
  - Major crimes may be allowed within roleplay, including bank robberies and high-speed pursuits.
  - All actions must still follow roleplay logic.

## Fail Roleplay (FRP)
Fail Roleplay is behavior that breaks realistic roleplay.
- Do not drive recklessly without a reason.
- Do not ignore roleplay events or other players' actions.
- Do not interfere with ongoing roleplay without consent.
- Consequences may include warnings, temporary bans, or permanent bans depending on severity.

## Voice Channel Rules
- Use your microphone responsibly and avoid disruptive noise.
- Do not interrupt ongoing roleplay events.
- Staff may mute or move disruptive players.
- Respect voice moderators and their instructions.

## Staff and Reporting
- Follow staff instructions.
- Report rule violations in the report channel with screenshots or evidence.
- Staff decisions are final; arguing with staff is not tolerated.

## Additional Rules
- Exploiting, cheating, and abusing bugs or glitches are forbidden.
- Stay in character; do not use metagaming or out-of-character advantages.
- Use realistic names and appearances. Offensive names are prohibited.
- Respect vehicles, property, and the server economy.
- Communicate clearly and respectfully; avoid excessive out-of-character chat in roleplay channels.
- Cooperate with others during roleplay scenarios.
- Report bugs and exploits. Using an exploit before reporting it may be punished.

## Roleplay Etiquette
- Wait your turn during roleplay scenarios.
- Follow staff and scenario leaders.
- Do not interrupt or rush events.
- Help new players understand roleplay rules.

## Vehicle Restrictions
- Restricted vehicles may only be driven by members with an applicable vehicle exemption role.
- Vehicle exemption roles: <@&1342600763817332818>, <@&1342600764593410139>, or <@&1342600763071004734>.
- Driving a restricted vehicle without an applicable exemption role may result in a strike.
- The detailed restricted vehicle list from the linked Google Doc could not be retrieved, so specific vehicle names have not been guessed."""

HUB_SERVER_GUIDELINES = """# GVRG Server Guidelines
- Respect all members. Harassment, hate speech, and personal attacks are prohibited.
- Do not spam messages, images, or blocks of text.
- Do not post NSFW content, illegal material, or graphic violence.
- Do not advertise servers, projects, or services without staff permission.
- Follow Discord's Terms of Service.
- Respect staff decisions.
- Do not impersonate other members, staff, or public figures.

By joining **Greenville Roleplay Genesis**, you agree to follow these rules and help maintain a fair, fun, and realistic roleplay environment."""

HUB_PLUS_INFO = "# GVRG Plus\n\n- GVRG Plus information will be available soon."

HUB_FAQ_INFO = """# Frequently Asked Questions
Common questions from civilians and new members.

## Getting Started
- **Why can't I see most channels?** Verify first to unlock the server.
- **How do I verify my Roblox account?** Use Bloxlink's verification command in the verification channel.
- **I verified but nothing changed.** Roles usually update within a minute; try refreshing Discord.
- **How do I become a Civilian?** Apply through the application channel after verifying.
- **Is there a free Civilian promotion?** Ask staff; availability changes over time.

## Vehicles and Ranks
- **Why can't I drive this vehicle?** It may require a rank you do not have. Use `-check-v` to see requirements.
- **What does Unlicensed mean?** You can roleplay as a civilian but cannot legally drive yet.
- **How do I get my in-game license?** Complete the in-game driving test or scenario.

## Roleplay and Rules
- **What is FRP?** Fail Roleplay means acting unrealistically in a way that breaks immersion.
- **Can I exceed the FRP speed limit?** No, unless a server rule or approved pass specifically allows it.
- **What if staff interrupt my scene?** Pause and follow their instructions immediately.

## Moderation and Appeals
- **How do I appeal a punishment?** Open a support ticket. Do not DM staff directly about an appeal."""

class GVRGInformationSelect(discord.ui.Select):
    def __init__(self):
        super().__init__(
            placeholder="Choose a type of information...",
            min_values=1,
            max_values=1,
            custom_id="gvrg_hub:information_type",
            options=[
                discord.SelectOption(
                    label="Server Guidelines", value="guidelines",
                    description="Discord and server rules",
                    emoji=discord.PartialEmoji.from_str("<:white_information:1534973892534472794>"),
                ),
                discord.SelectOption(
                    label="Roleplay Information", value="roleplay",
                    description="Peacetime levels and roleplay rules",
                    emoji=discord.PartialEmoji.from_str("<:white_information:1534973892534472794>"),
                ),
            ],
        )

    async def callback(self, interaction: discord.Interaction):
        if self.values[0] == "guidelines":
            view = GVRGHubView(HUB_SERVER_GUIDELINES, "detail-guidelines")
        else:
            view = GVRGHubView(HUB_ROLEPLAY_INFO, "detail-roleplay")
        await interaction.response.send_message(view=view, ephemeral=True)


class GVRGHubSelect(discord.ui.Select):
    def __init__(self):
        super().__init__(
            placeholder="Choose an information category...",
            min_values=1,
            max_values=1,
            custom_id="gvrg_hub:category",
            options=[
                discord.SelectOption(
                    label="Information", value="information",
                    description="Server guidelines or roleplay information",
                    emoji=discord.PartialEmoji.from_str("<:white_information:1534973892534472794>"),
                ),
                discord.SelectOption(
                    label="GVRG Plus", value="plus",
                    description="GVRG Plus information",
                    emoji=discord.PartialEmoji.from_str("<:white_star:1534973822871273524>"),
                ),
                discord.SelectOption(
                    label="FAQ", value="faq",
                    description="Frequently asked questions",
                    emoji=discord.PartialEmoji.from_str("<:white_handbook:1547436513187332206>"),
                ),
            ],
        )

    async def callback(self, interaction: discord.Interaction):
        selected = self.values[0]
        if selected == "information":
            await interaction.response.send_message(
                view=GVRGInformationView(), ephemeral=True
            )
        elif selected == "plus":
            await interaction.response.send_message(
                view=GVRGHubView(HUB_PLUS_INFO, "detail-plus"), ephemeral=True
            )
        else:
            await interaction.response.send_message(
                view=GVRGHubView(HUB_FAQ_INFO, "detail-faq"), ephemeral=True
            )


class GVRGInformationView(discord.ui.LayoutView):
    def __init__(self):
        super().__init__(timeout=180)
        container = discord.ui.Container()
        container.add_item(discord.ui.TextDisplay("# Information"))
        container.add_item(discord.ui.TextDisplay(
            "Choose whether you want to read the server guidelines or the roleplay rules."
        ))
        container.add_item(discord.ui.Separator())
        row = discord.ui.ActionRow()
        row.add_item(GVRGInformationSelect())
        container.add_item(row)
        container.add_item(discord.ui.Separator())
        container.add_item(discord.ui.TextDisplay("-# Greenville Roleplay Genesis"))
        self.add_item(container)


class GVRGHubView(discord.ui.LayoutView):
    def __init__(self, body=None, selected="home"):
        super().__init__(timeout=None if selected == "home" else 180)
        container = discord.ui.Container()
        if selected == "home":
            container.add_item(discord.ui.TextDisplay("# GVRG Hub"))
            container.add_item(discord.ui.TextDisplay(
                "Welcome to **GVRG Hub**! This channel contains information and resources to help you during your time at **Greenville Roleplay Genesis**. Please use the dropdown below to learn more."
            ))
        else:
            container.add_item(discord.ui.TextDisplay(body or "# GVRG Hub"))
        if selected == "home":
            container.add_item(discord.ui.Separator())
            row = discord.ui.ActionRow()
            row.add_item(GVRGHubSelect())
            container.add_item(row)
        container.add_item(discord.ui.Separator())
        container.add_item(discord.ui.TextDisplay("-# Greenville Roleplay Genesis"))
        self.add_item(container)


GVRG_HUB_CHANNEL_ID = 1532451689259335761  # server-information


@bot.command(name="hub-panel")
@commands.guild_only()
@commands.has_permissions(administrator=True)
async def hub_panel_command(ctx: commands.Context):
    """Post the GVRG Hub information panel in the configured server-information channel."""
    target = ctx.guild.get_channel(GVRG_HUB_CHANNEL_ID)
    if not isinstance(target, discord.TextChannel):
        await ctx.reply(
            "I couldn't find the configured **server-information** channel. "
            "Please verify GVRG_HUB_CHANNEL_ID.",
            mention_author=False,
        )
        return
    try:
        await target.send(view=GVRGHubView())
    except discord.Forbidden:
        await ctx.reply(
            f"I can't send the hub panel in {target.mention}. Check my View Channel and Send Messages permissions.",
            mention_author=False,
        )
        return
    await ctx.reply(f"GVRG Hub panel posted in {target.mention}.", mention_author=False)

# ---------- GVRG STAFF TEAM INFORMATION HUB (COMPONENTS V2) ----------

# Optional logo shown to the right of the title. Leave "" to hide it.
STAFF_HUB_LOGO_URL = ""

# Fill in the real links. Use None for "TBA" (the bot will say it isn't available yet).
STAFF_HUB_LINKS = {
    "database": {
        "label": "Department Database",
        "description": "Staff records and department data",
        "url": "https://docs.google.com/spreadsheets/d/1mNQE20cZppdsO3BVVooqMN_IBm9XfM1x0jcbZZm6HVI/edit?usp=sharing",
    },
    "handbook": {
        "label": "Department Handbook",
        "description": "Coming soon",
        "url": None,  # TBA - paste the handbook link here when ready
    },
    "moderation": {
        "label": "Moderation Guide",
        "description": "Coming soon",
        "url": None,  # TBA
    },
    "shift": {
        "label": "Shift Logger",
        "description": "Log your shifts",
        "url": "https://forms.gle/CaENsw2JCm47zBDy8",
    },
    "loa": {
        "label": "LOA Form",
        "description": "Request a Leave of Absence",
        "url": "https://forms.gle/U6zdZBYHWu56N8ko6",
    },
    "resignation": {
        "label": "Resignation Form",
        "description": "Submit a resignation request",
        "url": "https://forms.gle/jvpGeMqcFVVwMRgNA",
    },
}


class StaffHubLinkView(discord.ui.LayoutView):
    """Ephemeral reply containing the selected link (only the selecting user sees it)."""

    def __init__(self, link: dict):
        super().__init__(timeout=180)
        container = discord.ui.Container()  # no accent color = no sidebar

        container.add_item(discord.ui.TextDisplay(f"## {link['label']}"))

        if not link.get("url"):
            container.add_item(discord.ui.TextDisplay(
                "This resource is **not available yet** (TBA). Please check back later."
            ))
        else:
            container.add_item(discord.ui.TextDisplay(link["description"]))
            row = discord.ui.ActionRow()
            row.add_item(discord.ui.Button(
                label=f"Open {link['label']}",
                style=discord.ButtonStyle.link,
                url=link["url"],
            ))
            container.add_item(row)
            container.add_item(discord.ui.TextDisplay(f"-# Direct link: {link['url']}"))

        container.add_item(discord.ui.Separator(spacing=discord.SeparatorSpacing.small))
        container.add_item(discord.ui.TextDisplay(
            "-# This document is confidential. Do not share it."
        ))
        self.add_item(container)


class StaffHubSelect(discord.ui.Select):
    def __init__(self):
        super().__init__(
            placeholder="Select a resource...",
            min_values=1,
            max_values=1,
            custom_id="gvrg_staff_hub:links",
            options=[
                discord.SelectOption(
                    label=data["label"],
                    value=key,
                    description=data["description"][:100],
                )
                for key, data in STAFF_HUB_LINKS.items()
            ],
        )

    async def callback(self, interaction: discord.Interaction):
        # Documents are confidential: only Server Staff (or above) can open them.
        if not is_giveaway_manager(interaction.user):
            await interaction.response.send_message(
                "Only members of the Staff Team can use this menu.", ephemeral=True
            )
            return

        link = STAFF_HUB_LINKS.get(self.values[0])
        if link is None:
            await interaction.response.send_message(
                "That option no longer exists.", ephemeral=True
            )
            return

        await interaction.response.send_message(
            view=StaffHubLinkView(link), ephemeral=True
        )


class StaffHubView(discord.ui.LayoutView):
    """Persistent Staff Team Information panel (Components V2, no sidebar)."""

    def __init__(self):
        super().__init__(timeout=None)
        container = discord.ui.Container()  # accent_color intentionally unset

        title = discord.ui.TextDisplay("# GVRG | Staff Information")
        if STAFF_HUB_LOGO_URL:
            container.add_item(discord.ui.Section(
                title, accessory=discord.ui.Thumbnail(STAFF_HUB_LOGO_URL)
            ))
        else:
            container.add_item(title)

        container.add_item(discord.ui.TextDisplay(
            "Welcome to the Information Channel of the **<#1532490128281436210>**. "
            "This channel contains all information pertaining to employment, procedures, "
            "and expectations within the team.\n\n"
            "For any inquiries or concerns, feel free to contact anyone from the "
            "**Supervisory Team**."
        ))

        container.add_item(discord.ui.Separator(spacing=discord.SeparatorSpacing.small))
        container.add_item(discord.ui.TextDisplay(
            "## Important Links\n"
            "Use the dropdown below to select the resource you need. "
            "The link will be sent to you privately."
        ))

        row = discord.ui.ActionRow()
        row.add_item(StaffHubSelect())
        container.add_item(row)

        container.add_item(discord.ui.Separator(spacing=discord.SeparatorSpacing.small))
        container.add_item(discord.ui.TextDisplay(
            "***All documents belonging to the department are confidential. "
            "Any leaking may lead to a Staff Team Ban.***"
        ))

        self.add_item(container)


@bot.command(name="staff-hub-panel")
@commands.guild_only()
@commands.has_permissions(administrator=True)
async def staff_hub_panel_command(ctx: commands.Context, channel: discord.TextChannel = None):
    """Post the Staff Team Information. Usage: -staff-hub-panel [#channel]"""
    target = channel or ctx.channel
    try:
        await target.send(view=StaffHubView())
    except discord.Forbidden:
        await ctx.reply(
            f"I can't send the panel in {target.mention}. Check my View Channel and Send Messages permissions.",
            mention_author=False,
        )
        return
    if target.id != ctx.channel.id:
        await ctx.reply(f"Staff Team Information Hub posted in {target.mention}.", mention_author=False)

# ---------- LIVE RELOAD SYSTEM ----------
#
# -reload        Hot reload: re-reads this file and swaps the running bot over to
#                the new code without disconnecting from Discord.
# -reload all    Restarts the Python process in place (same container, so the
#                host panel keeps showing the server as running). Use this for
#                changes a hot reload cannot apply (see the notes below).
#
# What a hot reload applies:
#   - new / changed / removed prefix commands, slash commands, context menus
#   - changed event handlers (on_message, error handlers, ...)
#   - changed views, modals, helper functions, constants and role/channel IDs
#   - persistent views (re-registered against the new classes)
#   - background loops (old ones finish their current pass, new ones start)
#   - slash command sync with Discord
# What it cannot apply (use -reload all or restart from the panel):
#   - token.txt, intents, command_prefix, or anything else set in ModBot.__init__
#   - newly installed pip packages / edits to other .py files this file imports
#   - the on_ready startup work (presence, one-time migrations)
# Only user 993004784556724345 can run either command. The command message is deleted and
# the result is sent to that user privately (DM).
# Views/modals that are already open keep running the code they were created
# with until they expire; new interactions use the new code.

import sys
import time


class ReloadError(Exception):
    """A reload problem that is safe to show to the user. The running code is left untouched."""


def _tree_commands(tree):
    """Every global app command on a tree: slash commands, groups and context menus."""
    found, seen = [], set()
    for kwargs in (
        {},
        {"type": discord.AppCommandType.message},
        {"type": discord.AppCommandType.user},
    ):
        try:
            batch = tree.get_commands(**kwargs)
        except TypeError:
            continue
        for command in batch:
            if id(command) not in seen:
                seen.add(id(command))
                found.append(command)
    return found


def _prefix_commands(target):
    # The built-in help command belongs to the bot itself, not to this file.
    return [c for c in target.commands if c.name != "help"]


def _event_handlers(target):
    return {
        name: handler
        for name, handler in vars(target).items()
        if name.startswith("on_") and callable(handler)
    }


def _install_state(live, prefix_commands, tree_commands, events, tree_error):
    """Make the live bot's commands and handlers exactly match the given set."""
    for command in _prefix_commands(live):
        live.remove_command(command.name)
    live.tree.clear_commands(guild=None)
    for name in list(_event_handlers(live)):
        delattr(live, name)
    vars(live.tree).pop("on_error", None)

    for command in prefix_commands:
        live.add_command(command)
    for command in tree_commands:
        live.tree.add_command(command)
    for name, handler in events.items():
        setattr(live, name, handler)
    if tree_error is not None:
        live.tree.on_error = tree_error


async def hot_reload(live: commands.Bot, source_path: Path) -> dict:
    """Load the latest code from source_path into the running bot.

    The new code is compiled and executed against a throw-away staging bot first.
    The live bot is only touched once that succeeds, and it is rolled back if the
    switch-over itself fails, so a bad edit cannot take commands offline.
    """
    started = time.perf_counter()

    # 1) Read + compile. Syntax errors stop here with nothing changed.
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReloadError(f"Could not read {source_path.name}: {exc}")
    try:
        code = compile(source, str(source_path), "exec")
    except SyntaxError as exc:
        raise ReloadError(f"Syntax error on line {exc.lineno}: {exc.msg}")

    # 2) Execute into a fresh namespace. This builds a staging bot that is never
    #    connected; the live bot is not involved yet.
    namespace = {"__name__": "gvrg_reloaded", "__file__": str(source_path)}
    try:
        exec(code, namespace)
    except Exception as exc:
        traceback.print_exception(type(exc), exc, exc.__traceback__)
        raise ReloadError(f"The new code failed to load: {type(exc).__name__}: {exc}")

    staging = namespace.get("bot")
    new_class = namespace.get("ModBot")
    if (
        not isinstance(staging, commands.Bot)
        or staging is live
        or not hasattr(new_class, "load_runtime_components")
    ):
        raise ReloadError(
            "The new code does not define `bot = ModBot()` with load_runtime_components()."
        )

    # 3) Snapshot what is live now (for rollback and for the added/removed report).
    old_prefix = _prefix_commands(live)
    old_tree = _tree_commands(live.tree)
    old_events = _event_handlers(live)
    old_tree_error = vars(live.tree).get("on_error")

    new_prefix = _prefix_commands(staging)
    new_tree = _tree_commands(staging.tree)
    new_events = _event_handlers(staging)
    new_tree_error = vars(staging.tree).get("on_error")

    # 4) Switch the live bot over to the new commands, handlers, menus and views.
    try:
        _install_state(live, new_prefix, new_tree, new_events, new_tree_error)
        new_class.load_runtime_components(live)
    except Exception as exc:
        traceback.print_exception(type(exc), exc, exc.__traceback__)
        try:
            _install_state(live, old_prefix, old_tree, old_events, old_tree_error)
        except Exception as rollback_exc:
            print(f"[reload] Rollback failed: {rollback_exc!r}")
        raise ReloadError(
            f"Switching to the new code failed ({type(exc).__name__}: {exc}). "
            "The previous code was restored."
        )

    # Functions from the new code look up `bot` in their own namespace.
    namespace["bot"] = live

    # 5) Background loops: let the old ones finish the pass they are in, then start the new ones.
    old_loops = [v for v in globals().values() if isinstance(v, tasks.Loop)]
    new_loops = [v for v in namespace.values() if isinstance(v, tasks.Loop)]
    for loop in old_loops:
        loop.stop()
    deadline = time.monotonic() + 15
    while any(l.is_running() for l in old_loops) and time.monotonic() < deadline:
        await asyncio.sleep(0.25)
    for loop in old_loops:
        if loop.is_running():
            loop.cancel()
    loop_errors = []
    for loop in new_loops:
        try:
            if not loop.is_running():
                loop.start()
        except RuntimeError as exc:
            loop_errors.append(str(exc))

    # 6) Sync slash commands so Discord matches the code.
    synced_count, sync_error = None, None
    try:
        synced_count = len(await live.tree.sync())
    except discord.HTTPException as exc:
        sync_error = f"{type(exc).__name__}: {exc}"

    old_names = {c.name for c in old_tree}
    new_names = {c.name for c in _tree_commands(live.tree)}
    return {
        "prefix_count": len(_prefix_commands(live)),
        "slash_count": len(new_names),
        "synced_count": synced_count,
        "sync_error": sync_error,
        "added": sorted(new_names - old_names),
        "removed": sorted(old_names - new_names),
        "loops": len(new_loops),
        "loop_errors": loop_errors,
        "seconds": time.perf_counter() - started,
    }


RELOAD_ALLOWED_USER_ID = 993004784556724345


async def reload_permission(ctx: commands.Context) -> bool:
    """Only one specific user may reload or restart the bot."""
    return ctx.author.id == RELOAD_ALLOWED_USER_ID


def _reload_embed(title: str, description: str, ok: bool = True) -> discord.Embed:
    return discord.Embed(
        title=title,
        description=description,
        color=0x596744 if ok else 0xCC3333,
    )


async def delete_command_message(ctx: commands.Context):
    try:
        await ctx.message.delete()
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass


async def send_private(ctx: commands.Context, embed: discord.Embed):
    """Deliver a result only the command author can see.

    Discord only allows true ephemeral messages as replies to interactions
    (slash commands, buttons, ...). A prefix command like -reload has no
    interaction to respond to, so the result is sent to the author's DMs. If
    their DMs are closed, a short-lived channel message is used instead.
    """
    try:
        await ctx.author.send(embed=embed)
        return
    except (discord.Forbidden, discord.HTTPException):
        pass
    try:
        await ctx.send(content=ctx.author.mention, embed=embed, delete_after=15)
    except discord.HTTPException:
        pass


async def restart_process_in_place(ctx: commands.Context):
    """Disconnect cleanly, then re-launch this script inside the same process slot.

    The container/process the host panel is watching never exits, so the server
    stays "running" and the bot is back online within a few seconds.
    """
    await delete_command_message(ctx)
    await send_private(
        ctx,
        _reload_embed(
            "Restarting",
            "Restarting the bot process. It will be back online in a few seconds.",
        ),
    )
    print("[reload] Restarting process in place...")
    await ctx.bot.close()
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execv(sys.executable, [sys.executable, *sys.argv])
    except OSError as exc:
        print(f"[reload] In-place restart failed ({exc!r}); exiting so the host can restart it.")
        os._exit(1)


@bot.command(name="reload")
@commands.guild_only()
@commands.check(reload_permission)
async def reload_command(ctx: commands.Context, mode: str = "hot"):
    """-reload (live code reload) or -reload all (restart the process in place).

    The command message is deleted and the result is sent privately to the author.
    """
    mode = mode.lower()
    if mode == "full":  # older spelling of "all"
        mode = "all"
    if mode not in ("hot", "all"):
        await delete_command_message(ctx)
        await send_private(
            ctx,
            _reload_embed("Reload", "Usage: `-reload` or `-reload all`.", ok=False),
        )
        return

    lock = getattr(ctx.bot, "_gvrg_reload_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        ctx.bot._gvrg_reload_lock = lock
    if lock.locked():
        await delete_command_message(ctx)
        await send_private(
            ctx, _reload_embed("Reload", "A reload is already in progress.", ok=False)
        )
        return

    async with lock:
        if mode == "all":
            await restart_process_in_place(ctx)
            return

        try:
            async with ctx.typing():
                report = await hot_reload(ctx.bot, Path(__file__).resolve())
        except ReloadError as exc:
            embed = _reload_embed(
                "Reload Failed",
                f"```\n{str(exc)[:1500]}\n```\nNothing was changed. The bot is still running the previous code.",
                ok=False,
            )
        except Exception as exc:
            traceback.print_exception(type(exc), exc, exc.__traceback__)
            embed = _reload_embed(
                "Reload Failed",
                f"```\n{type(exc).__name__}: {str(exc)[:1400]}\n```\nCheck the console for details.",
                ok=False,
            )
        else:
            lines = [
                f"**Prefix commands:** {report['prefix_count']}",
                f"**Slash commands:** {report['slash_count']}"
                + (f" (synced {report['synced_count']} with Discord)" if report["synced_count"] is not None else ""),
                f"**Added:** {', '.join(report['added']) or 'None'}",
                f"**Removed:** {', '.join(report['removed']) or 'None'}",
                f"**Background tasks restarted:** {report['loops']}",
                f"**Time:** {report['seconds']:.1f}s",
            ]
            ok = report["sync_error"] is None and not report["loop_errors"]
            if report["sync_error"]:
                lines.append(
                    f"\nThe new code is live, but the Discord sync failed: `{report['sync_error'][:300]}`. "
                    "Run `-reload` again in a minute to retry the sync."
                )
            if report["loop_errors"]:
                lines.append("\nBackground task problem: " + "; ".join(report["loop_errors"])[:300])
            embed = _reload_embed(
                "Reload Complete" if ok else "Reload Completed With Warnings",
                "\n".join(lines),
                ok=ok,
            )

        await delete_command_message(ctx)
        await send_private(ctx, embed)


# ---------- EARLY ACCESS CODE PANELS (COMPONENTS V2) ----------
EA_DATA_FILE = str(Path(__file__).resolve().parent / "early_access_data.json")
EA_ROLE_OPTIONS = {
    "staff": {"label": "Staff", "role_ids": [1532987896414339072], "maximum": 5},
    "boosters": {"label": "Boosters", "role_ids": [1532452726988996658], "maximum": 4},
    "ea_pass": {"label": "Early Access Pass", "role_ids": [1562705128564334673], "maximum": 2},
    "wsp_ocso": {"label": "WSP & OCSO", "role_ids": [1532907083006218401, 1541653256751550464], "maximum": 6},
    "gvfd": {"label": "GVFD", "role_ids": [1532458061850218706], "maximum": 3},
    "dot": {"label": "DOT", "role_ids": [1532907151599734854], "maximum": 2},
}
EA_SYSTEMS = {
    "a": {"label": "Startup 1", "panel_title": "Early Access — Startup 1", "select_id": "gvrg_early_access:select"},
    "b": {"label": "Startup 2", "panel_title": "Early Access — Startup 2", "select_id": "gvrg_early_access:b:select"},
}
EA_LEGACY_GUILD_KEYS = ("code", "codes", "recipients", "panel_message_id", "panel_channel_id")

# Every Early Access claim, reset, code change and panel post is logged here.
EA_LOG_CHANNEL_ID = 1534091486314889236
EA_LOG_COLORS = {"info": 0x596744, "success": 0x2ECC71, "warn": 0xF1C40F, "error": 0xE74C3C}


async def log_early_access(guild, title: str, who, action: str, system_id: str = None,
                           details: list = None, level: str = "info", who_label: str = "User"):
    """Post one Early Access event to EA_LOG_CHANNEL_ID. Never raises, so logging can't break a claim or reset.

    Every entry carries who did it, what they did, which startup, and when. Codes are never written to the log.
    """
    try:
        now = discord.utils.utcnow()
        stamp = int(now.timestamp())
        embed = discord.Embed(title=title, color=EA_LOG_COLORS.get(level, EA_LOG_COLORS["info"]), timestamp=now)
        if who is not None:
            embed.add_field(name=who_label, value=f"{who.mention} (`{who.id}`)", inline=False)
        embed.add_field(name="Action", value=action, inline=False)
        if system_id in EA_SYSTEMS:
            embed.add_field(name="System", value=EA_SYSTEMS[system_id]["label"], inline=True)
        for name, value in (details or []):
            embed.add_field(name=name, value=str(value) or "—", inline=True)
        embed.add_field(name="Date & Time", value=f"<t:{stamp}:F> (<t:{stamp}:R>)", inline=False)
        embed.set_footer(text="Early Access Log")

        channel = bot.get_channel(EA_LOG_CHANNEL_ID)
        if channel is None:
            channel = await bot.fetch_channel(EA_LOG_CHANNEL_ID)
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
        return True
    except Exception as exc:
        print(f"[Early Access] Could not write to the log channel {EA_LOG_CHANNEL_ID}: {exc!r}")
        return False


class EAStorageError(Exception):
    """The Early Access data file could not be read or written safely."""


def _ea_lock(guild_id, system_id, kind="data"):
    """One asyncio lock per guild/startup/purpose. Stored on the live bot so a hot reload keeps the same locks."""
    locks = bot.__dict__.setdefault("_ea_locks", {})
    return locks.setdefault((int(guild_id), system_id, kind), asyncio.Lock())


def _ea_read_file_raw():
    """Read the EA file exactly as stored. A corrupt file is moved aside (never silently overwritten)."""
    if not os.path.exists(EA_DATA_FILE):
        return {"guilds": {}}
    try:
        with open(EA_DATA_FILE, "r", encoding="utf-8") as handle:
            content = handle.read().strip()
    except OSError as exc:
        raise EAStorageError(f"Could not read {EA_DATA_FILE}: {exc!r}") from exc
    if not content:
        return {"guilds": {}}
    try:
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            raise ValueError("top level is not an object")
        return parsed
    except ValueError as exc:
        backup = f"{EA_DATA_FILE}.corrupt-{int(time.time())}"
        try:
            os.replace(EA_DATA_FILE, backup)
            print(f"[Early Access] Data file was unreadable ({exc!r}); preserved as {backup}.")
        except OSError as move_exc:
            raise EAStorageError(f"Early Access data is corrupt and could not be preserved: {move_exc!r}") from move_exc
        return {"guilds": {}}


def _ea_write_file(file_data):
    """Atomic write: a crash mid-save can never leave a truncated data file."""
    tmp_path = f"{EA_DATA_FILE}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(file_data, handle, indent=4)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, EA_DATA_FILE)
    except OSError as exc:
        raise EAStorageError(f"Could not write {EA_DATA_FILE}: {exc!r}") from exc


def _ea_int_or_none(value):
    try:
        return int(value) if value not in (None, "", 0, "0") else None
    except (TypeError, ValueError):
        return None


def _ea_normalize_system(system):
    """Make one startup's record well-formed. Per-role legacy codes collapse into the single shared code."""
    legacy_codes = system.pop("codes", None)
    code = str(system.get("code") or "").strip()
    if not code and isinstance(legacy_codes, dict):
        code = next((str(v).strip() for v in legacy_codes.values() if str(v).strip()), "")
    if code:
        system["code"] = code
    else:
        system.pop("code", None)

    recipients = system.get("recipients")
    if not isinstance(recipients, dict):
        recipients = {}
    for key in EA_ROLE_OPTIONS:
        seen, cleaned = set(), []
        for uid in recipients.get(key, []) if isinstance(recipients.get(key, []), list) else []:
            uid = str(uid).strip()
            if uid.isdigit() and uid not in seen:
                seen.add(uid)
                cleaned.append(uid)
        recipients[key] = cleaned
    system["recipients"] = recipients
    system["panel_message_id"] = _ea_int_or_none(system.get("panel_message_id"))
    system["panel_channel_id"] = _ea_int_or_none(system.get("panel_channel_id"))
    return system


def _ea_normalize_file(file_data):
    """Migrate the old single-panel layout into systems['a'] and drop the legacy top-level keys."""
    if not isinstance(file_data.get("guilds"), dict):
        file_data["guilds"] = {}
    for gid, guild_data in list(file_data["guilds"].items()):
        if not isinstance(guild_data, dict):
            guild_data = file_data["guilds"][gid] = {}
        systems = guild_data.get("systems")
        if not isinstance(systems, dict):
            systems = guild_data["systems"] = {}
        legacy = {k: guild_data.pop(k) for k in EA_LEGACY_GUILD_KEYS if k in guild_data}
        if legacy and "a" not in systems:
            systems["a"] = legacy  # legacy data belonged to the first (only) panel
        for sid in list(systems):
            if not isinstance(systems[sid], dict):
                systems[sid] = {}
            _ea_normalize_system(systems[sid])
    return file_data


def load_ea_data():
    return _ea_normalize_file(_ea_read_file_raw())


def _new_ea_system_data():
    return _ea_normalize_system({})


def ea_guild_data(guild_id, system_id="a"):
    """Return (file_data, selected startup's data), migrating legacy data in memory."""
    file_data = load_ea_data()
    guild_data = file_data["guilds"].setdefault(str(guild_id), {"systems": {}})
    systems = guild_data.setdefault("systems", {})
    for sid in EA_SYSTEMS:
        systems.setdefault(sid, _new_ea_system_data())
    return file_data, systems[system_id]


def save_ea_guild_data(guild_id, system_id, system_data):
    """Persist one startup. Other startups are re-read from disk and left untouched."""
    file_data = load_ea_data()
    guild_data = file_data["guilds"].setdefault(str(guild_id), {"systems": {}})
    guild_data.setdefault("systems", {})[system_id] = _ea_normalize_system(dict(system_data))
    _ea_write_file(file_data)


def ea_recipient_ids(guild_data, key):
    ids = guild_data.get("recipients", {}).get(key, [])
    return {int(uid) for uid in ids if str(uid).isdigit()}


def _ea_member_has_claimed(data, user_id):
    return any(user_id in ea_recipient_ids(data, key) for key in EA_ROLE_OPTIONS)


def _ea_verify_reset(guild_id, system_id):
    """Re-read the raw file from disk and confirm the startup's code and claims are really gone."""
    raw = _ea_read_file_raw()
    guild_raw = raw.get("guilds", {}).get(str(guild_id), {})
    if any(k in guild_raw for k in ("code", "codes")):
        return False
    system_raw = guild_raw.get("systems", {}).get(system_id, {})
    if system_raw.get("code") or system_raw.get("codes"):
        return False
    recipients = system_raw.get("recipients", {})
    return isinstance(recipients, dict) and all(not recipients.get(key) for key in EA_ROLE_OPTIONS)


async def refresh_ea_panel(guild: discord.Guild, system_id: str, fallback_message: discord.Message = None):
    """Re-render a startup's saved panel with live counters.

    Returns True only when a panel message was really updated. If the saved message is gone or
    cannot be edited, the panel the member just used (fallback_message) is adopted; only if that
    is not possible is a replacement posted. Never reports success when nothing changed.
    """
    label = EA_SYSTEMS[system_id]["label"]
    async with _ea_lock(guild.id, system_id, "panel"):
        try:
            _, data = ea_guild_data(guild.id, system_id)
        except EAStorageError as exc:
            print(f"[Early Access] {label}: cannot refresh panel, storage error: {exc!r}")
            return False
        message_id = data.get("panel_message_id")
        channel_id = data.get("panel_channel_id")
        view = EarlyAccessPanelView(guild.id, system_id, data=data)

        channel = None
        if channel_id:
            channel = guild.get_channel_or_thread(int(channel_id))
            if channel is None:
                try:
                    channel = await guild.fetch_channel(int(channel_id))
                except (discord.NotFound, discord.Forbidden, discord.HTTPException) as exc:
                    print(f"[Early Access] {label}: could not fetch panel channel {channel_id}: {exc!r}")

        replace_allowed = False
        edited = False
        if channel is not None and message_id and hasattr(channel, "fetch_message"):
            try:
                panel_message = await channel.fetch_message(int(message_id))
                await panel_message.edit(view=view)
                edited = True
            except discord.Forbidden as exc:
                print(f"[Early Access] {label}: not allowed to edit panel {message_id}: {exc!r}")
            except discord.NotFound as exc:
                print(f"[Early Access] {label}: saved panel {message_id} no longer exists: {exc!r}")
                replace_allowed = True
            except Exception as exc:  # HTTPException, or a message that cannot be re-rendered
                print(f"[Early Access] {label}: editing panel {message_id} failed: {exc!r}")
                replace_allowed = True
        elif not message_id or not channel_id:
            print(f"[Early Access] {label}: no saved panel IDs.")

        saved_matches = bool(message_id) and fallback_message is not None and fallback_message.id == int(message_id)

        # Keep the panel the member actually clicked current too (also resets their dropdown choice).
        if fallback_message is not None and not saved_matches and fallback_message.author.id == bot.user.id:
            try:
                await fallback_message.edit(view=view)
                if not edited:
                    # The saved panel is missing/unusable but this one is a live panel for this startup: adopt it.
                    async with _ea_lock(guild.id, system_id, "data"):
                        _, fresh = ea_guild_data(guild.id, system_id)
                        fresh["panel_message_id"] = fallback_message.id
                        fresh["panel_channel_id"] = fallback_message.channel.id
                        save_ea_guild_data(guild.id, system_id, fresh)
                    print(f"[Early Access] {label}: adopted panel message {fallback_message.id}.")
                    return True
            except Exception as exc:
                print(f"[Early Access] {label}: editing the clicked panel failed: {exc!r}")
        if edited:
            return True

        if not (replace_allowed and channel is not None and hasattr(channel, "send")):
            return False
        try:
            replacement = await channel.send(view=view, allowed_mentions=discord.AllowedMentions.none())
        except Exception as exc:
            print(f"[Early Access] {label}: could not post a replacement panel: {exc!r}")
            return False
        try:
            async with _ea_lock(guild.id, system_id, "data"):
                _, fresh = ea_guild_data(guild.id, system_id)
                fresh["panel_message_id"] = replacement.id
                fresh["panel_channel_id"] = replacement.channel.id
                save_ea_guild_data(guild.id, system_id, fresh)
        except EAStorageError as exc:
            print(f"[Early Access] {label}: replacement panel {replacement.id} posted but its ID was not saved: {exc!r}")
            return False
        try:
            await channel.get_partial_message(int(message_id)).delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass
        print(f"[Early Access] {label}: replaced panel with message {replacement.id}.")
        return True


class EarlyAccessPanelView(discord.ui.LayoutView):
    """Components V2 early-access panel (no accent stripe) with live claim counters derived from saved claims."""

    def __init__(self, guild_id: int, system_id: str = "a", data: dict = None):
        super().__init__(timeout=None)
        if data is None:
            _, data = ea_guild_data(guild_id, system_id)
        info = EA_SYSTEMS[system_id]
        container = discord.ui.Container()
        container.add_item(discord.ui.TextDisplay(f"# {info['panel_title']}"))
        container.add_item(discord.ui.TextDisplay(
            f"Claim your early-access code for **{info['label']}**. Pick your group from the dropdown — "
            "you need the matching server role. Your code is sent by DM and each member can claim once."
        ))
        count_lines = []
        for key, option in EA_ROLE_OPTIONS.items():
            claimed = len(ea_recipient_ids(data, key))
            suffix = " — full" if claimed >= option["maximum"] else ""
            count_lines.append(f"**{option['label']}:** {claimed}/{option['maximum']} claimed{suffix}")
        container.add_item(discord.ui.TextDisplay("**Role claim totals**\n" + "\n".join(count_lines)))
        row = discord.ui.ActionRow()
        row.add_item(EarlyAccessSelect(guild_id, system_id))
        container.add_item(row)
        container.add_item(discord.ui.Separator(spacing=discord.SeparatorSpacing.small))
        container.add_item(discord.ui.TextDisplay("-# Greenville Roleplay Genesis"))
        self.add_item(container)


async def _ea_process_claim(interaction: discord.Interaction, system_id: str, key: str):
    """Validate, reserve a slot, DM the code, and roll the slot back if the DM fails.

    Returns (reply text, (outcome text, log level)); the outcome is what gets written to the Early Access log.
    """
    member, guild = interaction.user, interaction.guild
    label = EA_SYSTEMS[system_id]["label"]
    option = EA_ROLE_OPTIONS.get(key)
    if option is None:
        return "That early-access option is invalid.", ("Invalid option selected", "warn")

    member_role_ids = {role.id for role in member.roles}
    if not any(role_id in member_role_ids for role_id in option["role_ids"]):
        return (f"You need the **{option['label']}** role to receive this code.",
                (f"Denied: missing the {option['label']} role", "warn"))

    uid = str(member.id)
    async with _ea_lock(guild.id, system_id, "data"):
        _, data = ea_guild_data(guild.id, system_id)
        if _ea_member_has_claimed(data, member.id):
            return ((f"You've already claimed your **{label}** code. Each member can claim once per startup, "
                     "and your claim is already counted."),
                    ("Denied: already claimed", "warn"))
        if len(ea_recipient_ids(data, key)) >= option["maximum"]:
            return (f"The **{option['label']}** early-access limit has been reached ({option['maximum']}). No more codes can be issued for this group.",
                    (f"Denied: {option['label']} limit reached ({option['maximum']})", "warn"))
        code = str(data.get("code") or "").strip()
        if not code:
            return (f"The shared code for **{label}** has not been configured yet. Please contact staff.",
                    ("Denied: no code configured", "warn"))
        # Reserve the slot before the (slow) DM so simultaneous clicks cannot double-claim or exceed the limit.
        data["recipients"].setdefault(key, []).append(uid)
        save_ea_guild_data(guild.id, system_id, data)

    try:
        await member.send(
            f"Your **{option['label']}** early-access code for **Greenville Roleplay Genesis — {label}** is:\n\n"
            f"`{code}`\n\nKeep this code private."
        )
    except (discord.Forbidden, discord.HTTPException) as exc:
        print(f"[Early Access] {label}: DM to {member.id} failed ({type(exc).__name__}); releasing their slot.")
        try:
            async with _ea_lock(guild.id, system_id, "data"):
                _, data = ea_guild_data(guild.id, system_id)
                data["recipients"][key] = [u for u in data["recipients"].get(key, []) if u != uid]
                save_ea_guild_data(guild.id, system_id, data)
        except EAStorageError as store_exc:
            print(f"[Early Access] {label}: could not release slot for {member.id}: {store_exc!r}")
        return ("I couldn't DM you. Enable DMs from server members, then select your group again. You have not used a code slot.",
                ("DM failed: slot released, no code sent", "error"))

    return f"I've sent the **{option['label']}** code for **{label}** to your DMs.", ("Claimed: code sent by DM", "success")


class EarlyAccessSelect(discord.ui.Select):
    def __init__(self, guild_id: int, system_id: str = "a"):
        super().__init__(
            placeholder="Choose your early-access role...",
            min_values=1,
            max_values=1,
            custom_id=EA_SYSTEMS[system_id]["select_id"],
            options=[discord.SelectOption(label=v["label"], value=k) for k, v in EA_ROLE_OPTIONS.items()],
        )
        self.system_id = system_id

    async def callback(self, interaction: discord.Interaction):
        key = self.values[0]  # read before any await; the persistent view instance is shared between clicks
        system_id = self.system_id
        if interaction.guild is None or not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message("Use this menu in the server where it was posted.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)  # acknowledge inside Discord's 3-second window
        try:
            reply, (outcome, level) = await _ea_process_claim(interaction, system_id, key)
        except EAStorageError as exc:
            print(f"[Early Access] {EA_SYSTEMS[system_id]['label']}: storage error during claim: {exc!r}")
            reply = "I couldn't save your claim, so no code was sent. Please tell staff."
            outcome, level = "Error: claim could not be saved", "error"
        except Exception:
            print(f"[Early Access] {EA_SYSTEMS[system_id]['label']}: unexpected claim error:")
            traceback.print_exc()
            reply = "Something went wrong while processing your claim. Please try again or contact staff."
            outcome, level = "Error: unexpected failure while processing the claim", "error"
        try:
            await interaction.followup.send(reply, ephemeral=True)
        except discord.HTTPException as exc:
            print(f"[Early Access] Could not send claim reply to {interaction.user.id}: {exc!r}")
        # Log every interaction with the panel, whatever its outcome.
        group_label = EA_ROLE_OPTIONS.get(key, {}).get("label", key)
        await log_early_access(
            interaction.guild, "Early Access Claim", interaction.user,
            f"Selected **{group_label}** on the {EA_SYSTEMS[system_id]['label']} panel",
            system_id=system_id,
            details=[("Group", group_label), ("Result", outcome)],
            level=level,
        )
        # Always re-render: updates the live counters and clears the dropdown selection.
        if not await refresh_ea_panel(interaction.guild, system_id, interaction.message):
            print(f"[Early Access] {EA_SYSTEMS[system_id]['label']}: panel did not refresh after a claim interaction by {interaction.user.id}.")


class ChangeEarlyAccessCodeModal(discord.ui.Modal, title="Change Early Access Code"):
    code = discord.ui.TextInput(
        label="New shared code", placeholder="Used for every role group on this panel",
        style=discord.TextStyle.short, max_length=200, required=True,
    )

    def __init__(self, system_id: str):
        super().__init__()
        self.system_id = system_id

    async def on_submit(self, interaction: discord.Interaction):
        new_code = str(self.code.value).strip()
        if not new_code:
            await interaction.response.send_message("The code can't be blank. Nothing was changed.", ephemeral=True)
            return
        label = EA_SYSTEMS[self.system_id]["label"]
        try:
            async with _ea_lock(interaction.guild.id, self.system_id, "data"):
                _, data = ea_guild_data(interaction.guild.id, self.system_id)
                had_code = bool(str(data.get("code") or "").strip())
                data["code"] = new_code
                save_ea_guild_data(interaction.guild.id, self.system_id, data)
        except EAStorageError as exc:
            print(f"[Early Access] {label}: could not save new code: {exc!r}")
            await interaction.response.send_message("I couldn't save the new code. Nothing was changed; check the bot's logs.", ephemeral=True)
            await log_early_access(
                interaction.guild, "Early Access Code Change Failed", interaction.user,
                f"Tried to change the {label} code, but it could not be saved (nothing changed)",
                system_id=self.system_id, level="error", who_label="Staff Member",
            )
            return
        # The code itself is never written to the log.
        await log_early_access(
            interaction.guild, "Early Access Code Changed", interaction.user,
            f"{'Replaced' if had_code else 'Set'} the shared {label} code (value not logged)",
            system_id=self.system_id, details=[("Existing claims", "Not changed")],
            level="success", who_label="Staff Member",
        )
        await interaction.response.send_message(
            f"Updated the shared Early Access code for **{label}**. It applies to every role group on that panel. "
            "Existing claims were not changed.",
            ephemeral=True,
        )

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        print(f"[Early Access] Change-code modal error ({type(error).__name__}):")
        traceback.print_exception(type(error), error, error.__traceback__)
        try:
            if interaction.response.is_done():
                await interaction.followup.send("Something went wrong saving the code.", ephemeral=True)
            else:
                await interaction.response.send_message("Something went wrong saving the code.", ephemeral=True)
        except discord.HTTPException:
            pass


def _ea_component_custom_ids(components):
    found = set()
    for component in components or []:
        custom_id = getattr(component, "custom_id", None)
        if custom_id:
            found.add(custom_id)
        found |= _ea_component_custom_ids(getattr(component, "children", None))
    return found


def _ea_system_for_message(guild_id: int, message: discord.Message):
    """Identify which startup a message is the panel for: saved IDs first, then its dropdown's custom_id."""
    file_data = load_ea_data()
    systems = file_data["guilds"].get(str(guild_id), {}).get("systems", {})
    for sid in EA_SYSTEMS:
        if systems.get(sid, {}).get("panel_message_id") == message.id:
            return sid
    if message.author.id == bot.user.id:
        custom_ids = _ea_component_custom_ids(getattr(message, "components", None))
        for sid, info in EA_SYSTEMS.items():
            if info["select_id"] in custom_ids:
                return sid
    return None


@app_commands.guild_only()
async def change_ea_code_context_callback(interaction: discord.Interaction, message: discord.Message):
    try:
        system_id = _ea_system_for_message(interaction.guild.id, message)
    except EAStorageError as exc:
        print(f"[Early Access] Could not look up panel for context menu: {exc!r}")
        await interaction.response.send_message("I couldn't read the Early Access data. Check the bot's logs.", ephemeral=True)
        return
    if system_id is None:
        await interaction.response.send_message("This action only works on an official Early Access panel.", ephemeral=True)
        return
    await interaction.response.send_modal(ChangeEarlyAccessCodeModal(system_id))


change_ea_code_context_menu = app_commands.ContextMenu(
    name="Change EA Code", callback=change_ea_code_context_callback
)


async def _post_ea_panel(interaction: discord.Interaction, system_id: str):
    if interaction.guild is None or not isinstance(interaction.user, discord.Member) or not is_giveaway_manager(interaction.user):
        await interaction.response.send_message("Only Server Staff or higher can post an Early Access panel.", ephemeral=True)
        return
    channel = interaction.channel
    if channel is None or not hasattr(channel, "send"):
        await interaction.response.send_message("I couldn't find a channel to post the panel in.", ephemeral=True)
        return
    label = EA_SYSTEMS[system_id]["label"]
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        view = EarlyAccessPanelView(interaction.guild.id, system_id)
        message = await channel.send(view=view, allowed_mentions=discord.AllowedMentions.none())
    except EAStorageError as exc:
        print(f"[Early Access] {label}: could not load data to post panel: {exc!r}")
        await interaction.followup.send("I couldn't read the Early Access data, so no panel was posted. Check the bot's logs.", ephemeral=True)
        return
    except (discord.Forbidden, discord.HTTPException) as exc:
        print(f"[Early Access] {label}: could not post panel: {exc!r}")
        await interaction.followup.send("I couldn't post the panel here. I need permission to view and send messages in this channel.", ephemeral=True)
        return
    try:
        async with _ea_lock(interaction.guild.id, system_id, "data"):
            _, data = ea_guild_data(interaction.guild.id, system_id)
            data["panel_message_id"] = message.id
            data["panel_channel_id"] = message.channel.id
            save_ea_guild_data(interaction.guild.id, system_id, data)
    except EAStorageError as exc:
        print(f"[Early Access] {label}: panel posted but IDs not saved: {exc!r}")
        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass
        await interaction.followup.send("I couldn't save the panel's location, so I removed it. Check the bot's file permissions and try again.", ephemeral=True)
        return
    await interaction.followup.send(f"The **{label}** panel has been posted in {message.channel.mention}.", ephemeral=True)
    await log_early_access(
        interaction.guild, "Early Access Panel Posted", interaction.user,
        f"Posted the {label} panel",
        system_id=system_id, details=[("Channel", message.channel.mention), ("Message ID", f"`{message.id}`")],
        level="info", who_label="Staff Member",
    )


@bot.tree.command(name="early-access-1", description="Post the Early Access panel for Startup 1.")
@app_commands.guild_only()
async def early_access_panel_command(interaction: discord.Interaction):
    await _post_ea_panel(interaction, "a")


@bot.tree.command(name="early-access-2", description="Post the Early Access panel for Startup 2.")
@app_commands.guild_only()
async def early_access_2_panel_command(interaction: discord.Interaction):
    await _post_ea_panel(interaction, "b")


async def _reset_ea_claims(interaction: discord.Interaction, system_id: str):
    if interaction.guild is None or not isinstance(interaction.user, discord.Member) or not is_giveaway_manager(interaction.user):
        await interaction.response.send_message("Only Server Staff or higher can reset Early Access claims.", ephemeral=True)
        return
    label = EA_SYSTEMS[system_id]["label"]
    await interaction.response.defer(ephemeral=True, thinking=True)

    try:
        async with _ea_lock(interaction.guild.id, system_id, "data"):
            _, data = ea_guild_data(interaction.guild.id, system_id)
            claims_cleared = sum(len(ea_recipient_ids(data, key)) for key in EA_ROLE_OPTIONS)
            code_cleared = bool(str(data.get("code") or "").strip())
            # Fresh record: no code, no codes, no claims. Only this startup's panel location is kept.
            fresh = {
                "recipients": {key: [] for key in EA_ROLE_OPTIONS},
                "panel_message_id": data.get("panel_message_id"),
                "panel_channel_id": data.get("panel_channel_id"),
            }
            save_ea_guild_data(interaction.guild.id, system_id, fresh)
            verified = _ea_verify_reset(interaction.guild.id, system_id)
    except EAStorageError as exc:
        print(f"[Early Access] {label}: reset failed: {exc!r}")
        await interaction.followup.send(f"I couldn't reset **{label}** because the data file couldn't be written. Nothing was confirmed; check the bot's logs.", ephemeral=True)
        await log_early_access(
            interaction.guild, "Early Access Reset Failed", interaction.user,
            f"Tried to reset {label}, but the data file could not be written",
            system_id=system_id, level="error", who_label="Staff Member",
        )
        return
    if not verified:
        print(f"[Early Access] {label}: reset verification failed after saving.")
        await interaction.followup.send(f"I couldn't verify the reset for **{label}**. Please check the bot's file permissions and try again.", ephemeral=True)
        await log_early_access(
            interaction.guild, "Early Access Reset Failed", interaction.user,
            f"Reset {label}, but it could not be verified on disk",
            system_id=system_id, level="error", who_label="Staff Member",
        )
        return

    _, current = ea_guild_data(interaction.guild.id, system_id)
    had_panel = bool(current.get("panel_message_id") and current.get("panel_channel_id"))
    panel_refreshed = await refresh_ea_panel(interaction.guild, system_id)
    response = (
        f"**{label}** has been reset: its code is cleared and all claims are removed (counters are at zero). "
        "Staff must set a new code before eligible members can claim again."
    )
    if panel_refreshed:
        response += " The panel has been refreshed."
    elif not had_panel:
        response += f" No panel is saved for {label} yet; post one with `/early-access-{'1' if system_id == 'a' else '2'}`."
    else:
        response += (
            " **The reset succeeded, but I couldn't refresh the panel message** (see the bot's console log). "
            f"Repost it with `/early-access-{'1' if system_id == 'a' else '2'}`."
        )
    await interaction.followup.send(response, ephemeral=True)
    await log_early_access(
        interaction.guild, "Early Access Reset", interaction.user,
        f"Reset {label}: code cleared and all claims removed",
        system_id=system_id,
        details=[("Claims removed", claims_cleared),
                 ("Code cleared", "Yes" if code_cleared else "None was set"),
                 ("Panel refreshed", "Yes" if panel_refreshed else "No")],
        level="success", who_label="Staff Member",
    )


@bot.tree.command(name="reset-early-access-1", description="Reset claims and clear the code for Startup 1.")
@app_commands.guild_only()
async def reset_early_access_command(interaction: discord.Interaction):
    await _reset_ea_claims(interaction, "a")


@bot.tree.command(name="reset-early-access-2", description="Reset claims and clear the code for Startup 2.")
@app_commands.guild_only()
async def reset_early_access_2_command(interaction: discord.Interaction):
    await _reset_ea_claims(interaction, "b")


# ---------- SLASH COMMANDS ----------


@bot.tree.command(
    name="ticket-setup",
    description="Set up GVRG tickets, support roles, panel, categories, and transcripts."
)
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(
    panel_channel="Channel where the GVRG support panel will be posted.",
    transcript_channel="Channel where staff-saved transcripts will be sent.",
    general_category="Category for General Support tickets.",
    general_support_role="Support role for General Support tickets.",
    civilian_report_category="Category for Civilian Report tickets.",
    civilian_report_role="Support role for Civilian Report tickets.",
    staff_report_category="Category for Staff Report tickets.",
    staff_report_role="Support role for Staff Report tickets.",
    partnership_category="Category for Partnership tickets.",
    partnership_role="Support role for Partnership tickets.",
)
async def ticket_setup(
    interaction: discord.Interaction,
    panel_channel: discord.TextChannel,
    transcript_channel: discord.TextChannel,
    general_category: discord.CategoryChannel,
    general_support_role: discord.Role,
    civilian_report_category: discord.CategoryChannel,
    civilian_report_role: discord.Role,
    staff_report_category: discord.CategoryChannel,
    staff_report_role: discord.Role,
    partnership_category: discord.CategoryChannel,
    partnership_role: discord.Role,
):
    """Configure each ticket type with its own support role and transcript destination."""
    config, gdata = guild_config(interaction.guild.id)

    # Keep legacy global role storage for backwards compatibility, while the
    # category records below hold the actual per-ticket support roles.
    gdata["staff_roles"] = list({
        general_support_role.id,
        civilian_report_role.id,
        staff_report_role.id,
        partnership_role.id,
    })
    gdata["transcript_channel_id"] = transcript_channel.id

    # Save the four fixed GVRG support categories with their own support role.
    gdata["categories"] = {
        "general-support": {
            "name": PANEL_CATEGORIES["general-support"]["name"],
            "description": PANEL_CATEGORIES["general-support"]["description"],
            "category_id": general_category.id,
            "support_role_id": general_support_role.id,
        },
        "civilian-report": {
            "name": PANEL_CATEGORIES["civilian-report"]["name"],
            "description": PANEL_CATEGORIES["civilian-report"]["description"],
            "category_id": civilian_report_category.id,
            "support_role_id": civilian_report_role.id,
        },
        "staff-report": {
            "name": PANEL_CATEGORIES["staff-report"]["name"],
            "description": PANEL_CATEGORIES["staff-report"]["description"],
            "category_id": staff_report_category.id,
            "support_role_id": staff_report_role.id,
        },
        "partnership": {
            "name": PANEL_CATEGORIES["partnership"]["name"],
            "description": PANEL_CATEGORIES["partnership"]["description"],
            "category_id": partnership_category.id,
            "support_role_id": partnership_role.id,
        },
    }

    # Remove the standard panel when rerunning setup, but keep the separate
    # moderation-appeal panel intact.
    previous_panels = gdata.get("panels", {})
    for previous_key, previous in previous_panels.items():
        if previous_key == "moderation-appeal":
            continue
        previous_channel_id = previous.get("channel_id")
        previous_message_id = previous.get("message_id")
        if not previous_channel_id or not previous_message_id:
            continue
        previous_channel = interaction.guild.get_channel(int(previous_channel_id))
        if previous_channel is None:
            continue
        try:
            previous_message = await previous_channel.fetch_message(int(previous_message_id))
            await previous_message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException, ValueError):
            pass

    appeal_panel = gdata.get("panels", {}).get("moderation-appeal")
    gdata["panels"] = {"moderation-appeal": appeal_panel} if appeal_panel else {}
    save_config(config)

    panel_id = "1"
    view = TicketPanelView(
        str(interaction.guild.id),
        panel_id,
        gdata["categories"],
    )

    message = await panel_channel.send(view=view)

    gdata["panels"][panel_id] = {
        "channel_id": panel_channel.id,
        "message_id": message.id,
        "active": True,
    }
    save_config(config)

    await interaction.response.send_message(
        "GVRG ticket system is set up.\n"
        f"Panel: {panel_channel.mention}\n"
        f"Transcript channel: {transcript_channel.mention}\n"
        f"General Support role: {general_support_role.mention}\n"
        f"Civilian Report role: {civilian_report_role.mention}\n"
        f"Staff Report role: {staff_report_role.mention}\n"
        f"Partnership role: {partnership_role.mention}",
        ephemeral=True,
    )


@bot.tree.command(
    name="moderation-appeal-setup",
    description="Create a dedicated Moderation Appeal ticket panel.",
)
@app_commands.guild_only()
@app_commands.checks.has_permissions(administrator=True)
@app_commands.describe(
    panel_channel="Channel where the Moderation Appeal panel will be posted.",
    ticket_category="Discord category where appeal tickets will be created.",
    support_role_1="First role allowed to view and manage appeal tickets.",
    support_role_2="Optional second support role.",
    support_role_3="Optional third support role.",
    support_role_4="Optional fourth support role.",
    support_role_5="Optional fifth support role.",
)
async def moderation_appeal_setup(
    interaction: discord.Interaction,
    panel_channel: discord.TextChannel,
    ticket_category: discord.CategoryChannel,
    support_role_1: discord.Role,
    support_role_2: discord.Role = None,
    support_role_3: discord.Role = None,
    support_role_4: discord.Role = None,
    support_role_5: discord.Role = None,
):
    """Configure a standalone moderation-appeal panel with multiple support roles."""
    config, gdata = guild_config(interaction.guild.id)
    support_roles = [r for r in (support_role_1, support_role_2, support_role_3, support_role_4, support_role_5) if r]
    # Deduplicate role IDs while preserving the order selected in the command.
    support_roles = list({role.id: role for role in support_roles}.values())
    role_ids = [role.id for role in support_roles]
    gdata.setdefault("categories", {})["moderation-appeal"] = {
        "name": PANEL_CATEGORIES["moderation-appeal"]["name"],
        "description": PANEL_CATEGORIES["moderation-appeal"]["description"],
        "category_id": ticket_category.id,
        "support_role_ids": role_ids,
        # Keep the first role for compatibility with older bot versions.
        "support_role_id": role_ids[0],
    }
    gdata.setdefault("panels", {})

    old_panel = gdata["panels"].get("moderation-appeal", {})
    old_channel_id = old_panel.get("channel_id")
    old_message_id = old_panel.get("message_id")
    old_channel = interaction.guild.get_channel(int(old_channel_id)) if old_channel_id else None
    if old_channel and old_message_id:
        try:
            old_message = await old_channel.fetch_message(int(old_message_id))
            await old_message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException, ValueError):
            pass

    panel_id = "moderation-appeal"
    view = TicketPanelView(
        str(interaction.guild.id),
        panel_id,
        gdata["categories"],
        category_keys=["moderation-appeal"],
    )
    message = await panel_channel.send(view=view)
    gdata["panels"][panel_id] = {
        "channel_id": panel_channel.id,
        "message_id": message.id,
        "active": True,
    }
    save_config(config)

    await interaction.response.send_message(
        "Moderation Appeal panel created successfully.\n"
        f"Panel: {panel_channel.mention}\n"
        f"Ticket category: {ticket_category.mention}\n"
        "Support roles: " + ", ".join(role.mention for role in support_roles),
        ephemeral=True,
    )


# There are intentionally no other slash commands.
# Ticket actions are handled by the panel/buttons and the -close prefix command.


# ---------- STARTUP MIGRATION ----------

async def migrate_legacy_ticket_topics():
    """Migrate old TICKET_DATA topics into config and clear them from Discord."""
    config = load_config()
    changed = False

    for guild in bot.guilds:
        guild_data = config.get("guilds", {}).get(str(guild.id))
        if not isinstance(guild_data, dict):
            continue

        tickets = guild_data.setdefault("tickets", {})
        for channel in guild.text_channels:
            topic = channel.topic or ""
            if not topic.startswith("TICKET_DATA:"):
                continue
            try:
                data = json.loads(topic[len("TICKET_DATA:"):])
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(data, dict):
                continue

            tickets[str(channel.id)] = data
            changed = True
            try:
                await channel.edit(topic="")
            except discord.HTTPException:
                pass

    if changed:
        save_config(config)


@bot.event
async def on_ready():
    activity = discord.Activity(
        type=discord.ActivityType.watching, 
        name="Made by: Kermit"
    )
    await bot.change_presence(activity=activity)
    print(f"Logged in as {bot.user.name} | Prefix: '-' | Status: Watching Made by: Kermit")

    await migrate_legacy_ticket_topics()

    if not citation_warrant_sweep.is_running():
        citation_warrant_sweep.start()
    if not civres_expiry_sweep.is_running():
        civres_expiry_sweep.start()
    # Giveaways are stored on disk, so any giveaway whose end time passed while
    # the bot was offline is finished by this sweep as soon as the bot is back.
    if not giveaway_sweep.is_running():
        giveaway_sweep.start()
    # Staff of the Month polls close automatically; polls that expired while the
    # bot was offline are finished by this sweep as soon as the bot is back.
    if not sotm_sweep.is_running():
        sotm_sweep.start()
    # Welcome banner is cached locally, and the live member count channel is kept in sync.
    await cache_welcome_banner()
    if not member_count_sweep.is_running():
        member_count_sweep.start()


# --- EVIDENCE NOTICE / ON MESSAGE EVENT ---
EVIDENCE_CHANNEL_ID = 1532491179118166197
EVIDENCE_NOTICE_TITLE = "Evidence Notice:"


def build_evidence_notice_v2_payload():
    """Build the Evidence Notice as a real Discord Components V2 message.

    This is intentionally sent through the raw Discord API instead of
    discord.Embed, because an Embed is a legacy message component and does
    not produce the Components V2 container shown in the reference image.
    """
    return [{
        "type": 17,  # Container
        "components": [
            {
                "type": 10,  # Text Display
                "content": "# **Evidence Notice:**",
            },
            {
                "type": 10,  # Text Display
                "content": (
                    "> When you are sending the evidence part, ensure the evidence is sent in "
                    "<#1532491179118166197>! This is not optional.\n"
                    "> Next when you copy the link to the evidence part of the format, ensure you have the `|`\n"
                    "> symbol between the reasoning and evidence.\n\n"
                    "-# This is so the bot knows which one is the reasoning and evidence."
                ),
            },
            {
                "type": 14,  # Separator
                "spacing": 1,
            },
            {
                "type": 10,  # Text Display
                "content": "**If you need the symbol, copy it below:**\n```\n|\n```",
            },
        ],
    }]


async def send_evidence_notice_v2(channel):
    """Send the Evidence Notice as a genuine Components V2 message."""
    payload = build_evidence_notice_v2_payload()
    return await bot.http.request(
        discord.http.Route(
            "POST",
            "/channels/{channel_id}/messages",
            channel_id=channel.id,
        ),
        json={
            "components": payload,
            # IS_COMPONENTS_V2 (32768). Required for Components V2 messages.
            "flags": 32768,
        },
    )


async def is_evidence_notice_message(message):
    """Recognize both the old Embed notice and the new Components V2 notice."""
    if message.author.id != bot.user.id:
        return False

    # Remove the previous legacy Embed notice when upgrading to V2.
    if message.embeds and message.embeds[0].title == EVIDENCE_NOTICE_TITLE:
        return True

    try:
        raw = await fetch_raw_message(bot, message.channel.id, message.id)
    except (discord.HTTPException, discord.NotFound):
        return False

    for component in raw.get("components", []) or []:
        if component.get("type") != 17:
            continue
        for child in component.get("components", []) or []:
            if child.get("type") == 10 and EVIDENCE_NOTICE_TITLE in (child.get("content") or ""):
                return True

    return False


# --- TRANSCRIPT CHANNEL ---
# Transcript channel messages are left untouched; the bot no longer posts
# the outdated download/open-in-browser instruction notice.
def is_transcript_channel(channel) -> bool:
    """True for the transcript channel (hardcoded ID or the one saved by /ticket-setup)."""
    if channel is None:
        return False
    if channel.id == TRANSCRIPT_CHANNEL_ID:
        return True
    guild = getattr(channel, "guild", None)
    if guild is None:
        return False
    try:
        saved = load_config().get("guilds", {}).get(str(guild.id), {}).get("transcript_channel_id")
        return bool(saved) and int(saved) == channel.id
    except (TypeError, ValueError):
        return False



# ---------- TRAINING REQUESTS (COMPONENTS V2) ----------
TRAIN_REQUEST_CHANNEL_ID = 1562658397738770463


def training_v2_container(text: str, buttons: list | None = None):
    children = [{"type": 10, "content": text}]
    if buttons:
        children.append({"type": 1, "components": buttons})
    return [{"type": 17, "components": children}]


class TrainingRequestModal(discord.ui.Modal, title="Training Request"):
    roblox_discord_username = discord.ui.TextInput(
        label="Roblox // Discord Username",
        placeholder="Enter your Roblox and Discord username",
        max_length=100,
        required=True,
    )
    available_time = discord.ui.TextInput(
        label="Time Available for Training (Timestamp)",
        placeholder="Example: <t:1792861200:F>",
        max_length=100,
        required=True,
    )

    def to_components(self):
        """Serialize the inputs and append the training time note at the bottom of the modal."""
        components = super().to_components()
        components.append({
            "type": 10,  # Text Display component supported in Components V2 modals
            "content": "**Please be aware:** Training requires **20–50 minutes of free time**.",
        })
        return components

    async def on_submit(self, interaction: discord.Interaction):
        username = self.roblox_discord_username.value.strip()
        available = self.available_time.value.strip()
        import re as _re
        if not _re.fullmatch(r"<t:\d{9,12}:[tTdDfFR]>", available):
            await interaction.response.send_message(
                "Please enter a valid Discord timestamp, such as `<t:1792861200:F>`. Replace the number with the Unix timestamp for your available time.",
                ephemeral=True,
            )
            return

        channel = interaction.client.get_channel(TRAIN_REQUEST_CHANNEL_ID)
        if channel is None:
            try:
                channel = await interaction.client.fetch_channel(TRAIN_REQUEST_CHANNEL_ID)
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                await interaction.response.send_message("I couldn't find the training request channel. Please contact an administrator.", ephemeral=True)
                return

        request_text = (
            "# Training Request\n"
            f"**Submitted by:** <@{interaction.user.id}> (`{interaction.user.id}`)\n"
            f"**Roblox // Discord Username:** {username}\n"
            f"**Time Available for Training:** {available}\n\n"
            "**Please be aware:** Training requires **20–50 minutes of free time**.\n\n"
            "-# Please review this request and choose Accept or Deny."
        )
        buttons = [
            {"type": 2, "style": 3, "label": "Accept", "custom_id": f"trainreq:accept:{interaction.user.id}"},
            {"type": 2, "style": 4, "label": "Deny", "custom_id": f"trainreq:deny:{interaction.user.id}"},
        ]
        try:
            await interaction.client.http.request(
                discord.http.Route("POST", "/channels/{channel_id}/messages", channel_id=channel.id),
                json={"components": training_v2_container(request_text, buttons), "flags": 32768},
            )
        except discord.HTTPException as exc:
            await interaction.response.send_message("I couldn't post your request. Please try again later.", ephemeral=True)
            print(f"[Training Request] Could not post request: {exc!r}")
            return
        await interaction.response.send_message("Your training request has been submitted.", ephemeral=True)


class TrainingDenialModal(discord.ui.Modal, title="Deny Training Request"):
    reason = discord.ui.TextInput(
        label="Reason for denial",
        placeholder="Explain why the request is being denied",
        style=discord.TextStyle.paragraph,
        max_length=1000,
        required=True,
    )

    def __init__(self, requester_id: int):
        super().__init__(timeout=300)
        self.requester_id = requester_id

    async def on_submit(self, interaction: discord.Interaction):
        # Acknowledge immediately; fetching the user, sending the DM, and editing
        # the Components V2 message can take longer than Discord's 3-second limit.
        await interaction.response.defer(ephemeral=True, thinking=True)
        user = interaction.client.get_user(self.requester_id)
        if user is None:
            try:
                user = await interaction.client.fetch_user(self.requester_id)
            except (discord.NotFound, discord.HTTPException):
                user = None
        if user is None:
            await interaction.followup.send("I couldn't find the user to notify.", ephemeral=True)
            return
        sent = await send_v2_dm(
            interaction.client, user, "Training Request Denied",
            f"Your training request in **{interaction.guild.name if interaction.guild else 'the server'}** was denied.",
            [f"**Reason:** {self.reason.value.strip()}", f"**Reviewed by:** {interaction.user.mention}"],
        )
        if interaction.message:
            try:
                raw = await fetch_raw_message(interaction.client, interaction.channel_id, interaction.message.id)
                for container in raw.get("components", []) or []:
                    if container.get("type") == 17:
                        for child in container.get("components", []) or []:
                            if child.get("type") == 1:
                                for button in child.get("components", []) or []:
                                    if button.get("custom_id", "").startswith("trainreq:"):
                                        button["disabled"] = True
                await interaction.client.http.request(
                    discord.http.Route("PATCH", "/channels/{channel_id}/messages/{message_id}", channel_id=interaction.channel_id, message_id=interaction.message.id),
                    json={"components": raw.get("components", []), "flags": 32768},
                )
            except (discord.HTTPException, TypeError, ValueError) as exc:
                print(f"[Training Request] Could not disable reviewed buttons: {exc!r}")
        status = "The user was notified by DM." if sent else "The user could not be DM'd (their DMs may be closed)."
        await interaction.followup.send(f"Training request denied. {status}", ephemeral=True)


@bot.tree.command(name="trainrequest", description="Open the training request form.")
@app_commands.guild_only()
async def trainrequest_command(interaction: discord.Interaction):
    """Open the form directly; submitted requests are posted to the configured channel."""
    # Intentionally no permission check. This command opens the form directly,
    # without posting a separate panel or requiring a button click.
    await interaction.response.send_modal(TrainingRequestModal())


@bot.listen("on_interaction")
async def training_request_component_router(interaction: discord.Interaction):
    if interaction.type != discord.InteractionType.component or not interaction.data:
        return
    custom_id = interaction.data.get("custom_id", "")
    if not custom_id.startswith("trainreq:"):
        return
    try:
        _, action, requester_text = custom_id.split(":", 2)
        requester_id = int(requester_text)
    except (ValueError, TypeError):
        await interaction.response.send_message("This training request button is invalid.", ephemeral=True)
        return
    if action == "deny":
        await interaction.response.send_modal(TrainingDenialModal(requester_id))
        return
    if action == "accept":
        # Acknowledge the button immediately to prevent Discord's interaction timeout.
        await interaction.response.defer(ephemeral=True, thinking=True)
        user = interaction.client.get_user(requester_id)
        if user is None:
            try:
                user = await interaction.client.fetch_user(requester_id)
            except (discord.NotFound, discord.HTTPException):
                user = None
        if user is None:
            await interaction.followup.send("I couldn't find the user to notify.", ephemeral=True)
            return
        sent = await send_v2_dm(
            interaction.client, user, "Training Request Accepted",
            f"Your training request in **{interaction.guild.name if interaction.guild else 'the server'}** has been accepted.",
            [f"**Reviewed by:** {interaction.user.mention}", "Please coordinate your training time with the training team."],
        )
        if interaction.message:
            try:
                raw = await fetch_raw_message(interaction.client, interaction.channel_id, interaction.message.id)
                for container in raw.get("components", []) or []:
                    if container.get("type") == 17:
                        for child in container.get("components", []) or []:
                            if child.get("type") == 1:
                                for button in child.get("components", []) or []:
                                    if button.get("custom_id", "").startswith("trainreq:"):
                                        button["disabled"] = True
                await interaction.client.http.request(
                    discord.http.Route("PATCH", "/channels/{channel_id}/messages/{message_id}", channel_id=interaction.channel_id, message_id=interaction.message.id),
                    json={"components": raw.get("components", []), "flags": 32768},
                )
            except (discord.HTTPException, TypeError, ValueError) as exc:
                print(f"[Training Request] Could not disable reviewed buttons: {exc!r}")
        status = "The user was notified by DM." if sent else "The user could not be DM'd (their DMs may be closed)."
        await interaction.followup.send(f"Training request accepted. {status}", ephemeral=True)

# ---------- START-UP 1 ANNOUNCEMENT (COMPONENTS V2) ----------
STARTUP1_IMAGE_URL = "https://cdn.discordapp.com/attachments/1551819045056286770/1562700024251416607/image_13.png?ex=6adaf14f&is=6ad99fcf&hm=1710ed4e2819d6bc58e10e15d5efd831a3fb232ae5790c5ca11fe352f3ec182a"
STARTUP1_RULES_URL = "https://discord.com/channels/1532206036985974844/1532451689259335761"


@bot.command(name="start-up1")
@commands.guild_only()
async def startup1_command(ctx: commands.Context):
    """Post the Start-up 1 announcement as one Components V2 card with its image."""
    # Components V2 container has no accent_color, so it has no colored sidebar.
    payload = [{
        "type": 17,  # Container
        "components": [
            {
                "type": 10,  # Text Display
                "content": "# Startup 1",
            },
            {
                "type": 10,  # Text Display
                "content": (
                    "> Welcome to a Greenville Roleplay Genesis (GVRG) session! "
                    "Please follow the steps below before joining.\n\n"
                    "**Session Entry Steps**\n"
                    "- Set your visibility to Everyone.\n"
                    "- Review the ⁠driving-guidelines.\n"
                    "- React to the Session Start-Up post.\n"
                    "- Wait for the @Session ping and session link.\n"
                    "- Check PT status, join, and enjoy your session.\n\n"
                    f"**[Rules & Guidelines]({STARTUP1_RULES_URL})**\n\n"
                    "> All members must follow session rules and host instructions. "
                    "Failure to comply may result in disciplinary action.\n\n"
                    "**Have a great session!**"
                ),
            },
            {
                "type": 14,  # Separator
                "spacing": 1,
            },
            {
                "type": 12,  # Media Gallery, inside the same V2 container
                "items": [
                    {
                        "media": {"url": STARTUP1_IMAGE_URL},
                        "description": "Startup - 1",
                    }
                ],
            },
        ],
    }]

    try:
        await bot.http.request(
            discord.http.Route(
                "POST",
                "/channels/{channel_id}/messages",
                channel_id=ctx.channel.id,
            ),
            json={"components": payload, "flags": 32768},
        )
    except discord.HTTPException as exc:
        await ctx.reply(
            "I couldn't send the Start-up 1 panel. Check that the image link is still valid "
            "and that I have permission to send messages in this channel.",
            mention_author=False,
        )
        print(f"Start-up 1 panel send failed: {exc!r}")


# ---------- START-UP 2 ANNOUNCEMENT (COMPONENTS V2) ----------
STARTUP2_IMAGE_URL = "https://media.discordapp.net/attachments/1534314921322614859/1562868552997019668/image_15.png?ex=6adb8e43&is=6ada3cc3&hm=12741cd4be491b07114b984da75cc8ef70bd617910ecb7c87146912b131a6ade&=&format=webp&quality=lossless&width=1280&height=458"
STARTUP2_RULES_URL = "https://discord.com/channels/1532206036985974844/1532451689259335761"


@bot.command(name="start-up2")
@commands.guild_only()
async def startup2_command(ctx: commands.Context):
    """Post the Start-up 2 announcement as one Components V2 card with its image (same flow as -start-up1)."""
    # Components V2 container has no accent_color, so it has no colored sidebar.
    payload = [{
        "type": 17,  # Container
        "components": [
            {
                "type": 10,  # Text Display
                "content": "# Startup 2",
            },
            {
                "type": 10,  # Text Display
                "content": (
                    "> Welcome to a Greenville Roleplay Genesis (GVRG) session! "
                    "Please complete the following steps before joining.\n\n"
                    "**Session Entry Steps**\n"
                    "- Set your visibility to Everyone.\n"
                    "- Review the driving-guidelines.\n"
                    "- React to the Session Start-Up 2 post.\n"
                    "- Wait for the @Session ping containing the session link.\n"
                    "- Check PT status, join the session, and enjoy your time in GVRG.\n\n"
                    f"**[Rules & Guidelines]({STARTUP2_RULES_URL})**\n\n"
                    "> All members must follow session rules and host instructions. "
                    "Failure to comply may result in disciplinary action.\n\n"
                    "**Have a great session!**"
                ),
            },
            {
                "type": 14,  # Separator
                "spacing": 1,
            },
            {
                "type": 12,  # Media Gallery, inside the same V2 container
                "items": [
                    {
                        "media": {"url": STARTUP2_IMAGE_URL},
                        "description": "Startup - 2",
                    }
                ],
            },
        ],
    }]

    try:
        await bot.http.request(
            discord.http.Route(
                "POST",
                "/channels/{channel_id}/messages",
                channel_id=ctx.channel.id,
            ),
            json={"components": payload, "flags": 32768},
        )
    except discord.HTTPException as exc:
        await ctx.reply(
            "I couldn't send the Start-up 2 panel. Check that the image link is still valid "
            "and that I have permission to send messages in this channel.",
            mention_author=False,
        )
        print(f"Start-up 2 panel send failed: {exc!r}")


@bot.event
async def on_message(message: discord.Message):
    # Ignore the bot's own messages so the Evidence Notice does not loop.
    if message.author.bot:
        return

    if message.channel.id == EVIDENCE_CHANNEL_ID:
        # The user's message is NOT deleted.
        # Delete the existing Evidence Notice itself, then repost it as V2.
        try:
            async for old_message in message.channel.history(limit=50):
                if await is_evidence_notice_message(old_message):
                    try:
                        await old_message.delete()
                    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                        pass
                    break
        except discord.HTTPException as exc:
            print(f"Evidence Notice lookup failed: {exc!r}")

        try:
            await send_evidence_notice_v2(message.channel)
        except discord.Forbidden:
            print(
                f"Evidence Notice could not be sent: missing Send Messages permission "
                f"in channel {EVIDENCE_CHANNEL_ID}."
            )
        except discord.HTTPException as exc:
            print(f"Evidence Notice V2 send failed: {exc!r}")

        # IMPORTANT: prefix commands must still work in this channel.
        # The user's command/message is intentionally NOT deleted; only the
        # existing Evidence Notice is replaced.
        await bot.process_commands(message)
        return

    if is_transcript_channel(message.channel):
        # No generic download/open-in-browser notice is posted anymore.
        # Prefix commands must still work in this channel.
        await bot.process_commands(message)
        return

    # Keep all existing prefix commands working in every other channel.
    await bot.process_commands(message)


def get_server_emoji(guild: discord.Guild, name: str, fallback: str) -> str:
    """Return a server custom emoji by name, with a non-Unicode fallback."""
    emoji = discord.utils.get(guild.emojis, name=name)
    return str(emoji) if emoji else fallback


@bot.command(name="dm")
@commands.guild_only()
@commands.has_permissions(manage_messages=True)
async def dm_command(ctx, user: discord.User, *, message: str):
    """DM a specific Discord user and report whether the DM was sent."""
    checkmark = get_server_emoji(ctx.guild, "white_checkmark", ":white_checkmark:")
    xmark = get_server_emoji(ctx.guild, "white_xmark", ":white_xmark:")

    if not message.strip():
        await ctx.send(f"{xmark} Please provide a message to send.", delete_after=8)
        return

    try:
        dm_channel = user.dm_channel or await user.create_dm()
        await dm_channel.send(message)
    except discord.Forbidden:
        await ctx.send(
            f"{xmark} DM **not sent** to {user.mention}. The user's DMs are closed or the bot is blocked.",
            delete_after=10,
        )
        return
    except discord.HTTPException as e:
        await ctx.send(
            f"{xmark} DM **not sent** to {user.mention}. Discord returned an error: `{e}`",
            delete_after=10,
        )
        return
    except Exception as e:
        print(f"DM command error for {user.id}: {e}")
        await ctx.send(
            f"{xmark} DM **not sent** to {user.mention}. An unexpected error occurred.",
            delete_after=10,
        )
        return

    await ctx.send(
        f"{checkmark} DM **successfully sent** to {user.mention}.",
        delete_after=8,
    )


# --- ERROR HANDLERS ---
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, (commands.MissingRole, commands.MissingAnyRole)):
        await ctx.send("You do not possess the required role to execute prefix commands.", delete_after=8)
    elif isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("You lack the necessary permissions for this action.", delete_after=8)
    elif isinstance(error, commands.CheckFailure):
        await ctx.send("You do not possess the required role to use this command.", delete_after=8)
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"Missing argument: `{error.param.name}`. Example: `{ctx.prefix}{ctx.command.name} @User`", delete_after=8)
    else:
        print(f"Prefix Command Error: {error!r}")


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    print(f"App Command Error in '{interaction.command.name if interaction.command else 'Unknown'}': {error}")
    traceback.print_exception(type(error), error, error.__traceback__)

    if not interaction.response.is_done():
        await interaction.response.send_message("An error occurred while running this command.", ephemeral=True)


# =====================================================================
# --- STAFF MANAGEMENT: /hire, /resign, /terminate ---
# =====================================================================
# Ranks are ordered highest -> lowest. Each entry: (label, rank_role_id, tier).
# The /hire dropdown only offers these ranks. Command-level roles (High Command,
# Administration Team, Supervisor, Low Command) are NEVER picked by hand: the bot
# adds them automatically from the tier of the rank that was chosen.
HIRE_RANKS = [
    ("Server Director",      1532452702603444356, "high"),
    ("Server Overseer",      1532453040974594089, "high"),
    ("Server Manager",       1532455433707589814, "high"),
    ("Community Manager",    1535870760797732885, "high"),
    ("High Command",         1536260044977340536, "high"),
    ("Senior Administrator", 1532455580663287889, "admin"),
    ("Lead Administrator",   1532455673928093917, "admin"),
    ("Lead Supervisor",      1549661252589199421, "supervisor"),
    ("Junior Supervisor",    1549660428701929532, "supervisor"),
    ("Supervisor",           1532456149901639791, "supervisor"),
    ("Lead Moderator",       1532455515697713162, "low"),
    ("Senior Moderator",     1532462973455564940, "low"),
    ("Moderator",            1532455935455531252, "low"),
    ("Trial Moderator",      1535714661721317446, "trial"),
]

# The command-level role that goes with each tier (None = no command-level role).
HIRE_TIER_ROLES = {
    "high":       1536260044977340536,  # High Command
    "admin":      1535871041304404048,  # Administration Team
    "supervisor": 1532456149901639791,  # Supervisor
    "low":        1543131387991949403,  # Low Command
    "trial":      None,                 # Trial Moderators: Trial Moderator + Staff Team only
}

HIRE_STAFF_TEAM_ROLE = 1532987896414339072   # Staff Team (given to everyone hired)
HIRE_STAFF_DIVIDER_ROLE = None               # TODO: paste the ID of the `--staff--` role. Given to everyone EXCEPT Trial Moderators.
HIRE_TRIAL_ROLE = 1535714661721317446
ROLE_FORMER_STAFF = 1555347855592394893      # Assigned when a resignation is accepted

# Log channels
HIRE_LOG_CHANNEL_ID = 1562652079481421829
RESIGN_LOG_CHANNEL_ID = 1562652144774025217
TERMINATE_LOG_CHANNEL_ID = 1562652204421095496

# Staff welcome message (posted by /hire). Trial Moderators and all other ranks use different channels.
STAFF_TRIAL_WELCOME_CHANNEL_ID = 1532491429622841395   # Trial Moderator welcome messages only
STAFF_WELCOME_CHANNEL_ID = 1532491124688687354         # welcome messages for every other staff rank
STAFF_GUIDE_CHANNEL_ID = 1532490128281436210
STAFF_TRAINING_INFO_CHANNEL_ID = 1532491396496363590

HIRE_RANK_INDEX = {rid: i for i, (_, rid, _) in enumerate(HIRE_RANKS)}
HIRE_MIN_AUTH_INDEX = HIRE_RANK_INDEX[1536260044977340536]  # High Command and above may /hire, /terminate and handle resignations

# Every role that counts as "staff-related". /resign and /terminate remove these and nothing else.
STAFF_ROLE_IDS = (
    {rid for _, rid, _ in HIRE_RANKS}
    | {rid for rid in HIRE_TIER_ROLES.values() if rid}
    | {HIRE_STAFF_TEAM_ROLE}
    | ({HIRE_STAFF_DIVIDER_ROLE} if HIRE_STAFF_DIVIDER_ROLE else set())
)

STAFF_COLOR_HIRE = 0x596744
STAFF_COLOR_RESIGN = 0xE67E22
STAFF_COLOR_TERMINATE = 0xED4245
STAFF_COLOR_ACCEPT = 0x57F287

RESIGN_DATA_FILE = "staff_resign_requests.json"   # remembers each member's pending resignation request
RESIGN_REQUEST_TITLE = "Resignation Request"

# Termination appeals (submitted from the Appeal button in the termination DM)
STAFF_APPEAL_CHANNEL_ID = None    # TODO: channel where appeals are posted for review. Until set, appeals go to the Terminated Staff Log.
STAFF_APPEAL_DATA_FILE = "staff_appeals.json"   # remembers which terminations have already been appealed
STAFF_COLOR_APPEAL = 0x3498DB
_LOG_FAIL_NOTE_PLAIN = "\nThe action succeeded, but I could not post it to the log channel. Check my permissions there."


# --- shared helpers ---

def _hire_invoker_index(member: discord.Member):
    """Index of the member's highest staff rank in HIRE_RANKS (lower = more senior), or None."""
    indexes = [HIRE_RANK_INDEX[r.id] for r in member.roles if r.id in HIRE_RANK_INDEX]
    return min(indexes) if indexes else None


def _hire_roles_for(rank_index: int) -> list:
    """Ordered, de-duplicated list of role IDs to assign for the chosen rank (rank + command-level + staff roles)."""
    _, rank_role_id, tier = HIRE_RANKS[rank_index]
    role_ids = [rank_role_id]
    tier_role = HIRE_TIER_ROLES.get(tier)
    if tier_role:
        role_ids.append(tier_role)
    role_ids.append(HIRE_STAFF_TEAM_ROLE)
    if tier != "trial" and HIRE_STAFF_DIVIDER_ROLE:
        role_ids.append(HIRE_STAFF_DIVIDER_ROLE)
    return list(dict.fromkeys(role_ids))


def _staff_roles_held(member: discord.Member) -> list:
    """The member's staff-related roles, highest first."""
    return sorted((r for r in member.roles if r.id in STAFF_ROLE_IDS), key=lambda r: r.position, reverse=True)


def _can_manage_staff(member: discord.Member) -> bool:
    """High Command and above (or the server owner) may /hire, /terminate and accept/deny resignations."""
    if member.guild.owner_id == member.id:
        return True
    idx = _hire_invoker_index(member)
    return idx is not None and idx <= HIRE_MIN_AUTH_INDEX


def _bot_cannot_edit(guild: discord.Guild, member: discord.Member):
    """Return an error string if the bot can't edit this member's roles, else None."""
    if member.id == guild.owner_id:
        return "I can't change the roles of the server owner."
    if member.top_role >= guild.me.top_role:
        return f"I can't edit {member.mention} because their highest role is at or above my bot role."
    return None


def _fmt_roles(roles) -> str:
    return "\n".join(r.mention for r in roles) if roles else "None"


def _dm_status(ok: bool) -> str:
    return "Yes" if ok else "No (their DMs are closed)"


def _staff_log_embed(guild, member, title, color, fields):
    now = central_now()
    embed = discord.Embed(title=title, color=color, timestamp=now)
    embed.set_thumbnail(url=member.display_avatar.url)
    for name, value, inline in fields:
        embed.add_field(name=name, value=value, inline=inline)
    stamp = f"{discord.utils.format_dt(now, 'F')} ({discord.utils.format_dt(now, 'R')})"
    embed.add_field(name="Date & Time", value=stamp, inline=False)
    embed.set_footer(text=f"{guild.name} | Staff Management")
    return embed


def _staff_dm_embed(guild: discord.Guild, title: str, description: str, color: int) -> discord.Embed:
    embed = discord.Embed(title=title, description=description, color=color, timestamp=central_now())
    embed.set_footer(text=f"{guild.name} | Staff Management")
    return embed


async def _dm_member(user, embed: discord.Embed, view: discord.ui.View = None) -> bool:
    """DM a user. Never raises: returns False if their DMs are closed or the send fails."""
    try:
        kwargs = {"embed": embed}
        if view is not None:
            kwargs["view"] = view
        await user.send(**kwargs)
        return True
    except (discord.Forbidden, discord.HTTPException) as exc:
        print(f"[staff-dm] Could not DM {getattr(user, 'id', '?')}: {exc!r}")
        return False


async def _send_staff_log(guild: discord.Guild, channel_id: int, embed: discord.Embed) -> bool:
    """Send an embed to a log channel. Returns False (and prints why) if it couldn't be sent."""
    try:
        channel = guild.get_channel(channel_id) or await bot.fetch_channel(channel_id)
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
        return True
    except Exception as exc:
        print(f"[staff-log] Could not send to channel {channel_id}: {exc!r}")
        return False


_LOG_FAIL_NOTE = "\nThe action succeeded, but I could not post it to the log channel. Check my permissions there."


# --- /hire ---

def _hire_next_steps(rank_index: int) -> str:
    """The 'what to do next' sentence(s), shared by the welcome message and the DM."""
    if HIRE_RANKS[rank_index][2] == "trial":
        return (
            f"Please go through <#{STAFF_GUIDE_CHANNEL_ID}> and <#{STAFF_TRAINING_INFO_CHANNEL_ID}>. "
            "Make a training request using the GVRG Bot. (Command will be made soon)."
        )
    return (
        f"Please go through <#{STAFF_GUIDE_CHANNEL_ID}> before hosting and proceeding to do staff procedures. "
        "If you have any questions, ask!"
    )


async def _send_staff_welcome(guild: discord.Guild, member: discord.Member, rank_index: int) -> bool:
    """Post the staff welcome message (mentioning the new hire). Never raises.

    Trial Moderators are welcomed in their own channel; every other rank goes to the main staff welcome channel.
    """
    channel_id = STAFF_TRIAL_WELCOME_CHANNEL_ID if HIRE_RANKS[rank_index][2] == "trial" else STAFF_WELCOME_CHANNEL_ID
    try:
        channel = guild.get_channel(channel_id) or await bot.fetch_channel(channel_id)
        await channel.send(
            f"Welcome {member.mention} to the GVRG Staff Team. {_hire_next_steps(rank_index)}",
            allowed_mentions=discord.AllowedMentions(users=[member], roles=False, everyone=False),
        )
        return True
    except Exception as exc:
        print(f"[staff-welcome] Could not send welcome for {member.id}: {exc!r}")
        return False


@bot.tree.command(name="hire", description="Hire a member into the staff team at a chosen rank.")
@app_commands.guild_only()
@app_commands.describe(member="The member to hire.", rank="The staff rank to assign. Command-level roles are added automatically.")
@app_commands.choices(
    rank=[app_commands.Choice(name=label, value=str(rid)) for label, rid, _ in HIRE_RANKS]
)
async def hire_command(interaction: discord.Interaction, member: discord.Member, rank: app_commands.Choice[str]):
    guild = interaction.guild
    invoker = interaction.user

    # --- Permission checks ---
    if not _can_manage_staff(invoker):
        await interaction.response.send_message("You are not authorized to use `/hire`.", ephemeral=True)
        return
    is_owner = guild.owner_id == invoker.id
    invoker_index = _hire_invoker_index(invoker)

    rank_index = HIRE_RANK_INDEX[int(rank.value)]
    rank_label = HIRE_RANKS[rank_index][0]

    # You can only hire into ranks strictly below your own.
    if not is_owner and rank_index <= invoker_index:
        await interaction.response.send_message(
            f"You can only hire members into a rank below your own. **{rank_label}** is at or above your rank.",
            ephemeral=True,
        )
        return

    # --- Target checks ---
    if member.bot:
        await interaction.response.send_message("You can't hire a bot.", ephemeral=True)
        return
    problem = _bot_cannot_edit(guild, member)
    if problem:
        await interaction.response.send_message(problem, ephemeral=True)
        return

    existing_index = _hire_invoker_index(member)
    if existing_index is not None:
        existing_label, existing_id, _ = HIRE_RANKS[existing_index]
        if existing_id != HIRE_TRIAL_ROLE:
            await interaction.response.send_message(
                f"{member.mention} already holds **{existing_label}**. `/hire` is for new staff only, so use your promotion process instead.",
                ephemeral=True,
            )
            return
        if rank_index == HIRE_RANK_INDEX[HIRE_TRIAL_ROLE]:
            await interaction.response.send_message(
                f"{member.mention} is already a **Trial Moderator**.", ephemeral=True
            )
            return

    # --- Resolve roles ---
    role_ids = _hire_roles_for(rank_index)
    roles, missing = [], []
    for rid in role_ids:
        role = guild.get_role(rid)
        if role:
            roles.append(role)
        else:
            missing.append(rid)
    if missing:
        await interaction.response.send_message(
            "These role IDs no longer exist in this server: " + ", ".join(f"`{m}`" for m in missing),
            ephemeral=True,
        )
        return

    to_add = [r for r in roles if r not in member.roles]
    to_remove = []
    former_role = guild.get_role(ROLE_FORMER_STAFF)
    if former_role and former_role in member.roles:
        to_remove.append(former_role)  # re-hire: Former Staff is removed as part of the same update
    if existing_index is not None and rank_index != HIRE_RANK_INDEX[HIRE_TRIAL_ROLE]:
        trial_role = guild.get_role(HIRE_TRIAL_ROLE)
        if trial_role and trial_role in member.roles:
            to_remove.append(trial_role)  # trial -> full hire replaces the trial role

    too_high = [r for r in roles + to_remove if r >= guild.me.top_role]
    if too_high:
        await interaction.response.send_message(
            "I can't assign or remove " + ", ".join(r.mention for r in too_high)
            + ". Move my bot role above them in Server Settings > Roles.",
            ephemeral=True,
        )
        return

    await interaction.response.defer(ephemeral=True)
    reason = f"/hire by {invoker} ({invoker.id}): {rank_label}"
    try:
        # One atomic update: old roles (Former Staff / Trial) come off and the new staff roles go on together.
        remove_ids = {r.id for r in to_remove}
        new_roles = [r for r in member.roles if r != guild.default_role and r.id not in remove_ids] + to_add
        await member.edit(roles=new_roles, reason=reason)
    except discord.Forbidden:
        await interaction.followup.send("I don't have permission to manage that member's roles.", ephemeral=True)
        return
    except discord.HTTPException as exc:
        await interaction.followup.send(f"Discord rejected the role update: `{exc}`", ephemeral=True)
        return

    # --- Welcome message + DM (neither can stop the hire or the log) ---
    welcomed = await _send_staff_welcome(guild, member, rank_index)
    dm_ok = await _dm_member(member, _staff_dm_embed(
        guild,
        "Welcome to the Staff Team",
        f"Congratulations! You have been hired in **{guild.name}** as **{rank_label}**.\n\n"
        f"**Next steps**\n{_hire_next_steps(rank_index)}",
        STAFF_COLOR_HIRE,
    ))

    fields = [
        ("Hired Member", f"{member.mention}\n`{member.id}`", True),
        ("Hired By", f"{invoker.mention}\n`{invoker.id}`", True),
        ("Assigned Rank", f"**{rank_label}**", False),
        ("Roles Granted", _fmt_roles(to_add), False),
    ]
    if to_remove:
        fields.append(("Roles Removed", _fmt_roles(to_remove), False))
    fields.append(("DM Sent", _dm_status(dm_ok), True))
    fields.append(("Welcome Message", "Posted" if welcomed else "Failed to post", True))
    embed = _staff_log_embed(guild, member, "Staff Hired", STAFF_COLOR_HIRE, fields)
    logged = await _send_staff_log(guild, HIRE_LOG_CHANNEL_ID, embed)

    notes = ""
    if not welcomed:
        notes += "\nI could not post the welcome message. Check my permissions in the staff welcome channel."
    if not dm_ok:
        notes += "\nI could not DM them (their DMs are closed)."
    if not logged:
        notes += _LOG_FAIL_NOTE
    await interaction.followup.send(
        f"{member.mention} has been hired as **{rank_label}**." + notes,
        ephemeral=True,
        allowed_mentions=discord.AllowedMentions.none(),
    )


# --- /resign (request -> Accept / Deny) ---

_resign_busy = set()  # message IDs currently being processed, so a double click can't run twice


def _resign_pending_get(member_id: int):
    return load_json(RESIGN_DATA_FILE, {}).get(str(member_id))


def _resign_pending_set(member_id: int, message_id: int):
    data = load_json(RESIGN_DATA_FILE, {})
    data[str(member_id)] = message_id
    save_json(RESIGN_DATA_FILE, data)


def _resign_pending_clear(member_id: int):
    data = load_json(RESIGN_DATA_FILE, {})
    if data.pop(str(member_id), None) is not None:
        save_json(RESIGN_DATA_FILE, data)


def _close_resign_embed(original: discord.Embed, title: str, color: int, status: str, extras) -> discord.Embed:
    """Copy the request embed and mark it as handled (keeps the original request details and time)."""
    embed = discord.Embed.from_dict(original.to_dict())
    embed.title = title
    embed.color = color
    for i, field in enumerate(embed.fields):
        if field.name == "Status":
            embed.set_field_at(i, name="Status", value=status, inline=field.inline)
        elif field.name == "Date & Time":
            embed.set_field_at(i, name="Requested", value=field.value, inline=field.inline)
    for name, value, inline in extras:
        embed.add_field(name=name, value=value, inline=inline)
    now = central_now()
    embed.add_field(
        name="Handled",
        value=f"{discord.utils.format_dt(now, 'F')} ({discord.utils.format_dt(now, 'R')})",
        inline=False,
    )
    return embed


def _resign_request_is_open(message: discord.Message) -> bool:
    return bool(message.embeds) and message.embeds[0].title == RESIGN_REQUEST_TITLE


async def _find_member(guild: discord.Guild, member_id: int):
    member = guild.get_member(member_id)
    if member is not None:
        return member
    try:
        return await guild.fetch_member(member_id)
    except discord.HTTPException:
        return None


async def _accept_resignation(interaction: discord.Interaction, member_id: int):
    guild = interaction.guild
    message = interaction.message
    if not _can_manage_staff(interaction.user):
        await interaction.response.send_message("You are not authorized to accept resignations.", ephemeral=True)
        return
    if message.id in _resign_busy or not _resign_request_is_open(message):
        await interaction.response.send_message("This request has already been handled.", ephemeral=True)
        return

    _resign_busy.add(message.id)
    try:
        member = await _find_member(guild, member_id)
        if member is None:
            await interaction.response.send_message(
                "That member is no longer in the server, so I can't change their roles. You can deny the request instead.",
                ephemeral=True,
            )
            return
        removed = _staff_roles_held(member)
        if not removed:
            await interaction.response.send_message(
                f"{member.mention} doesn't hold any staff roles anymore, so there is nothing to remove.",
                ephemeral=True,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        former = guild.get_role(ROLE_FORMER_STAFF)
        if former is None:
            await interaction.response.send_message("The Former Staff role no longer exists in this server.", ephemeral=True)
            return
        blocked = [r for r in removed + [former] if r >= guild.me.top_role]
        if blocked:
            await interaction.response.send_message(
                "I can't process this because these roles are at or above my bot role: "
                + ", ".join(r.mention for r in blocked),
                ephemeral=True,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return
        problem = _bot_cannot_edit(guild, member)
        if problem:
            await interaction.response.send_message(problem, ephemeral=True, allowed_mentions=discord.AllowedMentions.none())
            return

        await interaction.response.defer()
        removed_ids = {r.id for r in removed}
        new_roles = [r for r in member.roles if r != guild.default_role and r.id not in removed_ids]
        if former not in new_roles:
            new_roles.append(former)
        try:
            await member.edit(
                roles=new_roles,
                reason=f"Resignation accepted by {interaction.user} ({interaction.user.id})",
            )
        except discord.HTTPException as exc:
            await interaction.followup.send(f"I couldn't update their roles: `{exc}`", ephemeral=True)
            return

        dm_ok = await _dm_member(member, _staff_dm_embed(
            guild,
            "Resignation Accepted",
            f"Your resignation from the **{guild.name}** staff team has been accepted. "
            "Your staff roles have been removed and you now hold the Former Staff role.\n\n"
            "Thank you for your service.",
            STAFF_COLOR_ACCEPT,
        ))
        _resign_pending_clear(member_id)
        embed = _close_resign_embed(
            message.embeds[0], "Resignation Accepted", STAFF_COLOR_ACCEPT, "Accepted",
            [
                ("Handled By", f"{interaction.user.mention}\n`{interaction.user.id}`", True),
                ("DM Sent", _dm_status(dm_ok), True),
                ("Staff Roles Removed", _fmt_roles(removed), False),
                ("Role Assigned", former.mention, False),
            ],
        )
        await interaction.edit_original_response(embed=embed, view=None)
        if not dm_ok:
            await interaction.followup.send("Accepted, but I could not DM them (their DMs are closed).", ephemeral=True)
    finally:
        _resign_busy.discard(message.id)


class ResignDenyModal(discord.ui.Modal, title="Deny Resignation"):
    reason = discord.ui.TextInput(
        label="Reason for denial",
        style=discord.TextStyle.paragraph,
        placeholder="This reason will be sent to the member.",
        max_length=1000,
        required=True,
    )

    def __init__(self, member_id: int, message: discord.Message):
        super().__init__()
        self.member_id = member_id
        self.message = message

    async def on_submit(self, interaction: discord.Interaction):
        guild = interaction.guild
        message = self.message
        if not _can_manage_staff(interaction.user):
            await interaction.response.send_message("You are not authorized to deny resignations.", ephemeral=True)
            return
        if message.id in _resign_busy or not _resign_request_is_open(message):
            await interaction.response.send_message("This request has already been handled.", ephemeral=True)
            return

        _resign_busy.add(message.id)
        try:
            await interaction.response.defer(ephemeral=True)
            reason = str(self.reason.value)
            user = await _find_member(guild, self.member_id)
            if user is None:
                try:
                    user = await bot.fetch_user(self.member_id)
                except discord.HTTPException:
                    user = None
            dm_ok = False
            if user is not None:
                dm_ok = await _dm_member(user, _staff_dm_embed(
                    guild,
                    "Resignation Denied",
                    f"Your resignation from the **{guild.name}** staff team has been denied. "
                    "You keep all of your current roles.\n\n"
                    f"**Reason**\n{reason}",
                    STAFF_COLOR_TERMINATE,
                ))
            _resign_pending_clear(self.member_id)
            embed = _close_resign_embed(
                message.embeds[0], "Resignation Denied", STAFF_COLOR_TERMINATE, "Denied",
                [
                    ("Handled By", f"{interaction.user.mention}\n`{interaction.user.id}`", True),
                    ("DM Sent", _dm_status(dm_ok), True),
                    ("Denial Reason", reason, False),
                ],
            )
            await message.edit(embed=embed, view=None)
            await interaction.followup.send(
                "Resignation denied." + ("" if dm_ok else " I could not DM them (their DMs are closed)."),
                ephemeral=True,
            )
        finally:
            _resign_busy.discard(message.id)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        print(f"[resign] Deny modal error: {error!r}")
        traceback.print_exception(type(error), error, error.__traceback__)
        msg = "Something went wrong while denying this request."
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)


class ResignAcceptButton(discord.ui.DynamicItem[discord.ui.Button], template=r"staff_resign:accept:(?P<member_id>\d+)"):
    """Persistent: the member's ID lives in the custom_id, so it keeps working after restarts."""

    def __init__(self, member_id: int):
        super().__init__(discord.ui.Button(
            label="Accept Resignation",
            style=discord.ButtonStyle.success,
            custom_id=f"staff_resign:accept:{member_id}",
        ))
        self.member_id = member_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button, match, /):
        return cls(int(match["member_id"]))

    async def callback(self, interaction: discord.Interaction):
        await _accept_resignation(interaction, self.member_id)


class ResignDenyButton(discord.ui.DynamicItem[discord.ui.Button], template=r"staff_resign:deny:(?P<member_id>\d+)"):
    def __init__(self, member_id: int):
        super().__init__(discord.ui.Button(
            label="Deny Resignation",
            style=discord.ButtonStyle.danger,
            custom_id=f"staff_resign:deny:{member_id}",
        ))
        self.member_id = member_id

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button, match, /):
        return cls(int(match["member_id"]))

    async def callback(self, interaction: discord.Interaction):
        if not _can_manage_staff(interaction.user):
            await interaction.response.send_message("You are not authorized to deny resignations.", ephemeral=True)
            return
        if interaction.message.id in _resign_busy or not _resign_request_is_open(interaction.message):
            await interaction.response.send_message("This request has already been handled.", ephemeral=True)
            return
        await interaction.response.send_modal(ResignDenyModal(self.member_id, interaction.message))


@bot.tree.command(name="resign", description="Submit a request to resign from the staff team.")
@app_commands.guild_only()
async def resign_command(interaction: discord.Interaction):
    guild = interaction.guild
    member = interaction.user
    held = _staff_roles_held(member)
    if not held:
        await interaction.response.send_message("You don't hold any staff roles.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True)

    # One open request per member.
    pending_id = _resign_pending_get(member.id)
    if pending_id:
        try:
            log_channel = guild.get_channel(RESIGN_LOG_CHANNEL_ID) or await bot.fetch_channel(RESIGN_LOG_CHANNEL_ID)
            existing = await log_channel.fetch_message(pending_id)
            if _resign_request_is_open(existing):
                await interaction.followup.send(
                    "You already have a resignation request waiting for review.", ephemeral=True
                )
                return
        except discord.HTTPException:
            pass  # the old request message is gone, so allow a new one

    embed = _staff_log_embed(guild, member, RESIGN_REQUEST_TITLE, STAFF_COLOR_RESIGN, [
        ("Resigning Member", f"{member.mention}\n`{member.id}`", False),
        ("Staff Roles", _fmt_roles(held), False),
        ("Status", "Pending review", False),
    ])
    view = discord.ui.View(timeout=None)
    view.add_item(ResignAcceptButton(member.id))
    view.add_item(ResignDenyButton(member.id))
    try:
        channel = guild.get_channel(RESIGN_LOG_CHANNEL_ID) or await bot.fetch_channel(RESIGN_LOG_CHANNEL_ID)
        sent = await channel.send(embed=embed, view=view, allowed_mentions=discord.AllowedMentions.none())
    except Exception as exc:
        print(f"[resign] Could not post resignation request for {member.id}: {exc!r}")
        await interaction.followup.send(
            "I couldn't submit your request. Please contact server management.", ephemeral=True
        )
        return

    _resign_pending_set(member.id, sent.id)
    await interaction.followup.send(
        "Your resignation request has been submitted for review. Your roles stay as they are until it is accepted, "
        "and you'll get a DM with the decision.",
        ephemeral=True,
    )


# --- /terminate ---

def _terminate_precheck(guild: discord.Guild, invoker: discord.Member, target: discord.Member):
    """Return an error message, or None if the termination may proceed."""
    if not _can_manage_staff(invoker):
        return "You are not authorized to use `/terminate`."
    if target.bot:
        return "You can't terminate a bot."
    if target.id == invoker.id:
        return "You can't terminate yourself. Use `/resign` instead."
    if target.id == guild.owner_id:
        return "The server owner can't be terminated."
    if not _staff_roles_held(target):
        return f"{target.mention} doesn't hold any staff roles."
    if guild.owner_id != invoker.id:
        invoker_index = _hire_invoker_index(invoker)
        target_index = _hire_invoker_index(target)
        if target_index is not None and target_index <= invoker_index:
            return "You can only terminate staff members ranked below you."
    return _bot_cannot_edit(guild, target)


async def _log_termination_to_mod_logs(guild, invoker, target, removed, reason_text, evidence_text,
                                       reference: int, dm_ok: bool) -> bool:
    """Record a successful termination in the moderation logs channel. Never raises; returns False on failure.

    `reference` is the unix time of the termination, so this entry, the Terminated Staff Log entry and the
    DM all show the same moment.
    """
    description = (
        f"**Terminated Member:** {target.mention} ({target})\n"
        f"**User ID:** `{target.id}`\n\n"
        f"**Terminated By:** {invoker.mention} ({invoker})\n"
        f"**Executor ID:** `{invoker.id}`\n\n"
        f"**Reason:** {reason_text}\n\n"
        f"**Evidence:** {evidence_text}\n\n"
        f"**Staff Roles Removed:** {_fmt_roles(removed)}\n"
        f"**Member Notified by DM:** {'Yes' if dm_ok else 'No (their DMs are closed)'}\n\n"
        f"**Date & Time:** <t:{reference}:F> (<t:{reference}:R>)"
    )
    embed = discord.Embed(
        title=f"Staff Termination | Reference {reference}",
        description=description[:4000],
        color=0xCC3333,
    )
    embed.set_footer(text=f"Moderator: @{invoker.name} | ID: {target.id}")
    try:
        channel = guild.get_channel(MOD_LOG_CHANNEL_ID) or await guild.fetch_channel(MOD_LOG_CHANNEL_ID)
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
        return True
    except Exception as exc:
        print(f"[terminate] Could not post to the moderation logs channel {MOD_LOG_CHANNEL_ID}: {exc!r}")
        return False


class TerminateModal(discord.ui.Modal, title="Terminate Staff Member"):
    reason = discord.ui.TextInput(
        label="Reason",
        style=discord.TextStyle.paragraph,
        placeholder="Why is this staff member being terminated?",
        max_length=1000,
        required=True,
    )
    evidence = discord.ui.TextInput(
        label="Evidence",
        style=discord.TextStyle.paragraph,
        placeholder="Supporting evidence (message links, screenshots links, case numbers, etc.)",
        max_length=1000,
        required=True,
    )

    def __init__(self, target: discord.Member):
        super().__init__()
        self.target = target

    async def on_submit(self, interaction: discord.Interaction):
        guild = interaction.guild
        invoker = interaction.user
        target = guild.get_member(self.target.id) or self.target  # fresh role data

        problem = _terminate_precheck(guild, invoker, target)
        if problem:
            await interaction.response.send_message(problem, ephemeral=True)
            return

        removed = _staff_roles_held(target)
        blocked = [r for r in removed if r >= guild.me.top_role]
        if blocked:
            await interaction.response.send_message(
                "I can't remove " + ", ".join(r.mention for r in blocked)
                + ". Move my bot role above them in Server Settings > Roles.",
                ephemeral=True,
                allowed_mentions=discord.AllowedMentions.none(),
            )
            return

        await interaction.response.defer(ephemeral=True)
        removed_ids = {r.id for r in removed}
        new_roles = [r for r in target.roles if r != guild.default_role and r.id not in removed_ids]
        try:
            await target.edit(
                roles=new_roles,
                reason=f"/terminate by {invoker} ({invoker.id}): {str(self.reason.value)[:200]}",
            )
        except discord.Forbidden:
            await interaction.followup.send("I don't have permission to manage that member's roles.", ephemeral=True)
            return
        except discord.HTTPException as exc:
            await interaction.followup.send(f"Discord rejected the role update: `{exc}`", ephemeral=True)
            return

        _resign_pending_clear(target.id)  # any open resignation request no longer applies

        # Internal reference ties the DM's Appeal button, termination record and appeal together.
        reference = int(central_now().timestamp())
        reason_text = str(self.reason.value)
        evidence_text = str(self.evidence.value)

        # Use the same sequential case number shown by -caselogs / -modlogs / -moglogs.
        case_id = None
        try:
            case_data = load_data()
            if not isinstance(case_data, dict):
                case_data = {"next_case": 1000, "users": {}}
            if not isinstance(case_data.get("users"), dict):
                case_data["users"] = {}
            try:
                case_id = int(case_data.get("next_case", 1000))
            except (TypeError, ValueError):
                case_id = 1000
            case_data["next_case"] = case_id + 1
            case_data["users"].setdefault(str(target.id), [])
            if not isinstance(case_data["users"][str(target.id)], list):
                case_data["users"][str(target.id)] = []
            case_reason = reason_text + (f" | Evidence: {evidence_text}" if evidence_text else "")
            case_data["users"][str(target.id)].append({
                "case_id": case_id,
                "type": "Staff Termination",
                "moderator": invoker.name,
                "reason": case_reason,
                "evidence": evidence_text,
                "timestamp": reference,
                "termination_reference": reference,
                "terminated_by_id": invoker.id,
            })
            save_data(case_data)
        except Exception as exc:
            print(f"[terminate] Could not add termination to case logs for {target.id}: {exc!r}")

        # Remember exactly which roles were removed, so an accepted appeal can restore them.
        try:
            _termination_record_save(target.id, reference, {
                "guild_id": guild.id,
                "user_id": target.id,
                "reference": reference,
                "removed_role_ids": [r.id for r in removed],
                "reason": reason_text,
                "evidence": evidence_text,
                "terminated_by": invoker.id,
                "terminated_at": reference,
            })
        except Exception as exc:
            print(f"[terminate] Could not save the termination record for {target.id}: {exc!r}")

        dm_embed = _staff_dm_embed(
            guild,
            "Staff Position Terminated",
            f"Your staff position in **{guild.name}** has been terminated, and your staff roles have been removed.\n\n"
            "If you believe this decision was made in error, you may submit an appeal using the button below.",
            STAFF_COLOR_TERMINATE,
        )
        dm_embed.add_field(name="Reason", value=reason_text, inline=False)
        dm_embed.add_field(name="Evidence", value=evidence_text, inline=False)
        dm_embed.add_field(name="Case Number", value=f"`#{case_id}`" if case_id is not None else "Unavailable", inline=False)
        appeal_view = discord.ui.View(timeout=None)
        appeal_view.add_item(StaffAppealButton(target.id, reference))
        dm_ok = await _dm_member(target, dm_embed, appeal_view)

        embed = _staff_log_embed(guild, target, "Staff Terminated", STAFF_COLOR_TERMINATE, [
            ("Terminated Member", f"{target.mention}\n`{target.id}`", True),
            ("Terminated By", f"{invoker.mention}\n`{invoker.id}`", True),
            ("Reason", reason_text, False),
            ("Evidence", evidence_text, False),
            ("Staff Roles Removed", _fmt_roles(removed), False),
            ("DM Sent", _dm_status(dm_ok), True),
            ("Case Number", f"`#{case_id}`" if case_id is not None else "Unavailable", True),
        ])
        logged = await _send_staff_log(guild, TERMINATE_LOG_CHANNEL_ID, embed)
        mod_logged = await _log_termination_to_mod_logs(
            guild, invoker, target, removed, reason_text, evidence_text, reference, dm_ok
        )
        notes = "" if dm_ok else (
            "\nI could not DM them (their DMs are closed), so they did not receive the reason, evidence or Appeal button."
        )
        await interaction.followup.send(
            f"{target.mention} has been terminated and their staff roles removed."
            + notes + ("" if logged else _LOG_FAIL_NOTE_PLAIN)
            + ("" if mod_logged else "\nI could not post this termination to the moderation logs channel. Check my permissions there."),
            ephemeral=True,
            allowed_mentions=discord.AllowedMentions.none(),
        )

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        print(f"[terminate] Modal error: {error!r}")
        traceback.print_exception(type(error), error, error.__traceback__)
        msg = "Something went wrong while processing the termination."
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)


@bot.tree.command(name="terminate", description="Terminate a staff member and remove their staff roles.")
@app_commands.guild_only()
@app_commands.describe(member="The staff member to terminate.")
async def terminate_command(interaction: discord.Interaction, member: discord.Member):
    problem = _terminate_precheck(interaction.guild, interaction.user, member)
    if problem:
        await interaction.response.send_message(problem, ephemeral=True, allowed_mentions=discord.AllowedMentions.none())
        return
    await interaction.response.send_modal(TerminateModal(member))


# --- Termination appeals (Appeal button in the termination DM) ---

def _appeal_key(user_id: int, reference: int) -> str:
    return f"{user_id}:{reference}"


def _appeal_already_submitted(user_id: int, reference: int) -> bool:
    return _appeal_key(user_id, reference) in load_json(STAFF_APPEAL_DATA_FILE, {})


def _appeal_mark_submitted(user_id: int, reference: int):
    data = load_json(STAFF_APPEAL_DATA_FILE, {})
    data[_appeal_key(user_id, reference)] = int(central_now().timestamp())
    save_json(STAFF_APPEAL_DATA_FILE, data)


async def _get_appeal_channel():
    channel_id = STAFF_APPEAL_CHANNEL_ID or TERMINATE_LOG_CHANNEL_ID
    return bot.get_channel(channel_id) or await bot.fetch_channel(channel_id)


class StaffAppealModal(discord.ui.Modal, title="Termination Appeal"):
    user_id_input = discord.ui.TextInput(
        label="User ID",
        placeholder="Your Discord user ID",
        max_length=25,
        required=True,
    )
    termination_reason = discord.ui.TextInput(
        label="Reason for Termination",
        style=discord.TextStyle.paragraph,
        placeholder="Why were you terminated?",
        max_length=1000,
        required=True,
    )
    appeal_reason = discord.ui.TextInput(
        label="Why Should the Termination Be Removed?",
        style=discord.TextStyle.paragraph,
        placeholder="Explain why this decision should be overturned.",
        max_length=1000,
        required=True,
    )
    evidence = discord.ui.TextInput(
        label="Evidence",
        style=discord.TextStyle.paragraph,
        placeholder="Links to screenshots, messages or other supporting evidence.",
        max_length=1000,
        required=False,
    )

    def __init__(self, user_id: int, reference: int, message: discord.Message = None):
        super().__init__()
        self.user_id = user_id
        self.reference = reference
        self.message = message

    async def on_submit(self, interaction: discord.Interaction):
        user = interaction.user
        if user.id != self.user_id:
            await interaction.response.send_message("This appeal belongs to a different account.", ephemeral=True)
            return
        if _appeal_already_submitted(self.user_id, self.reference):
            await interaction.response.send_message("You have already submitted an appeal for this termination.")
            return

        await interaction.response.defer()
        submitted_id = str(self.user_id_input.value).strip()
        id_matches = submitted_id == str(user.id)

        try:
            channel = await _get_appeal_channel()
        except discord.HTTPException as exc:
            print(f"[appeal] Could not reach the appeal channel: {exc!r}")
            await interaction.followup.send(
                "Your appeal could not be delivered. Please contact server management directly."
            )
            return

        embed = _staff_log_embed(channel.guild, user, "Termination Appeal", STAFF_COLOR_APPEAL, [
            ("Appellant", f"{user.mention}\n`{user.id}`", True),
            ("Reference ID", f"`{self.reference}`", True),
            ("User ID Provided", f"`{submitted_id}`" + ("" if id_matches else " (does not match this account)"), False),
            ("Reason for Termination", str(self.termination_reason.value), False),
            ("Why the Termination Should Be Removed", str(self.appeal_reason.value), False),
            ("Evidence", str(self.evidence.value).strip() or "None provided", False),
            ("Status", "Pending review", False),
        ])
        review_view = discord.ui.View(timeout=None)
        review_view.add_item(StaffAppealAcceptButton(self.user_id, self.reference))
        review_view.add_item(StaffAppealDenyButton(self.user_id, self.reference))
        try:
            appeal_message = await channel.send(
                embed=embed, view=review_view, allowed_mentions=discord.AllowedMentions.none()
            )
        except discord.HTTPException as exc:
            print(f"[appeal] Could not post appeal from {user.id}: {exc!r}")
            await interaction.followup.send(
                "Your appeal could not be delivered. Please contact server management directly."
            )
            return

        _appeal_mark_submitted(self.user_id, self.reference)
        try:
            _appeal_record_submitted(self.user_id, self.reference, channel.guild.id, appeal_message)
        except Exception as exc:
            print(f"[appeal] Could not save the appeal record for {self.user_id}: {exc!r}")
        if self.message is not None:
            try:
                await self.message.edit(view=None)  # the appeal has been sent, so remove the button
            except discord.HTTPException:
                pass
        await interaction.followup.send(
            "Your appeal has been submitted and will be reviewed by the staff team. "
            "You will be contacted if more information is needed."
        )

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        print(f"[appeal] Modal error: {error!r}")
        traceback.print_exception(type(error), error, error.__traceback__)
        msg = "Something went wrong while submitting your appeal. Please try again or contact server management."
        if interaction.response.is_done():
            await interaction.followup.send(msg)
        else:
            await interaction.response.send_message(msg)


class StaffAppealButton(discord.ui.DynamicItem[discord.ui.Button], template=r"staff_appeal:(?P<user_id>\d+):(?P<reference>\d+)"):
    """Persistent: the user and termination reference live in the custom_id, so it works after restarts."""

    def __init__(self, user_id: int, reference: int):
        super().__init__(discord.ui.Button(
            label="Appeal",
            style=discord.ButtonStyle.primary,
            custom_id=f"staff_appeal:{user_id}:{reference}",
        ))
        self.user_id = user_id
        self.reference = reference

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button, match, /):
        return cls(int(match["user_id"]), int(match["reference"]))

    async def callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.user_id:
            await interaction.response.send_message("This button is not for you.", ephemeral=True)
            return
        if _appeal_already_submitted(self.user_id, self.reference):
            await interaction.response.send_message("You have already submitted an appeal for this termination.")
            return
        await interaction.response.send_modal(StaffAppealModal(self.user_id, self.reference, interaction.message))


# --- Appeal review (Accept / Deny buttons on a submitted appeal) ---
#
# staff_terminations.json remembers, for every termination, which staff roles were removed and (once an
# appeal is submitted) the appeal's status: "pending" -> "accepted" or "denied". A reviewed appeal can never
# be processed again: its buttons are removed and its saved status is no longer "pending".

STAFF_TERMINATION_DATA_FILE = "staff_terminations.json"
_appeal_busy = set()   # appeal message IDs being processed right now, so a double click can't run twice


def _termination_record_get(user_id: int, reference: int):
    return load_json(STAFF_TERMINATION_DATA_FILE, {}).get(_appeal_key(user_id, reference))


def _termination_record_save(user_id: int, reference: int, record: dict):
    data = load_json(STAFF_TERMINATION_DATA_FILE, {})
    data[_appeal_key(user_id, reference)] = record
    save_json(STAFF_TERMINATION_DATA_FILE, data)


def _appeal_record_submitted(user_id: int, reference: int, guild_id: int, message: discord.Message):
    """Mark the appeal as pending and remember which message holds it."""
    data = load_json(STAFF_TERMINATION_DATA_FILE, {})
    key = _appeal_key(user_id, reference)
    # Terminations from before role records existed have no saved roles (removed_role_ids stays None).
    record = data.get(key) or {
        "guild_id": guild_id, "user_id": user_id, "reference": reference, "removed_role_ids": None,
    }
    record["appeal"] = {
        "status": "pending",
        "message_id": message.id,
        "channel_id": message.channel.id,
        "submitted_at": int(central_now().timestamp()),
    }
    data[key] = record
    save_json(STAFF_TERMINATION_DATA_FILE, data)


def _appeal_is_pending(user_id: int, reference: int) -> bool:
    record = _termination_record_get(user_id, reference) or {}
    return (record.get("appeal") or {}).get("status") == "pending"


def _appeal_set_decision(user_id: int, reference: int, status: str, reviewer_id: int, reason: str = None):
    data = load_json(STAFF_TERMINATION_DATA_FILE, {})
    record = data.get(_appeal_key(user_id, reference))
    if record is None:
        return
    appeal = record.setdefault("appeal", {})
    appeal["status"] = status
    appeal["reviewed_by"] = reviewer_id
    appeal["reviewed_at"] = int(central_now().timestamp())
    if reason is not None:
        appeal["decision_reason"] = reason
    save_json(STAFF_TERMINATION_DATA_FILE, data)


def _close_appeal_embed(original: discord.Embed, title: str, color: int, status: str, extras) -> discord.Embed:
    """Copy the appeal embed and mark it as reviewed (keeps what the member wrote and when they submitted it)."""
    embed = discord.Embed.from_dict(original.to_dict())
    embed.title = title
    embed.color = color
    for i, field in enumerate(embed.fields):
        if field.name == "Status":
            embed.set_field_at(i, name="Status", value=status, inline=field.inline)
        elif field.name == "Date & Time":
            embed.set_field_at(i, name="Submitted", value=field.value, inline=field.inline)
    for name, value, inline in extras:
        embed.add_field(name=name, value=value, inline=inline)
    now = central_now()
    embed.add_field(
        name="Reviewed",
        value=f"{discord.utils.format_dt(now, 'F')} ({discord.utils.format_dt(now, 'R')})",
        inline=False,
    )
    return embed


class _UnknownUser:
    """Stand-in used in a log entry when the appellant's account can't be looked up."""

    def __init__(self, user_id: int, guild: discord.Guild):
        self.id = user_id
        self.name = str(user_id)
        self.mention = f"<@{user_id}>"
        self.display_avatar = guild.me.display_avatar

    def __str__(self):
        return str(self.id)


async def _log_appeal_decision(guild, appellant, reviewer, reference: int, record: dict, accepted: bool,
                               decision_reason: str, restored_text: str, dm_ok: bool):
    """Record an appeal decision in the Terminated Staff Log and the moderation logs channel.

    Never raises. Returns (staff_log_ok, mod_log_ok).
    """
    record = record or {}
    verdict = "Accepted" if accepted else "Denied"
    now = central_now()
    ts = int(now.timestamp())

    fields = [
        ("Appellant", f"{appellant.mention}\n`{appellant.id}`", True),
        ("Reviewed By", f"{reviewer.mention}\n`{reviewer.id}`", True),
        ("Decision", verdict, True),
        ("Reference ID", f"`{reference}`", True),
        ("DM Sent", _dm_status(dm_ok), True),
    ]
    if record.get("reason"):
        fields.append(("Original Termination Reason", str(record["reason"])[:1024], False))
    if accepted:
        fields.append(("Staff Roles Restored", restored_text[:1024], False))
    else:
        fields.append(("Denial Reason", (decision_reason or "")[:1024], False))
    staff_embed = _staff_log_embed(
        guild, appellant, f"Termination Appeal {verdict}",
        STAFF_COLOR_ACCEPT if accepted else STAFF_COLOR_TERMINATE, fields,
    )
    staff_ok = await _send_staff_log(guild, TERMINATE_LOG_CHANNEL_ID, staff_embed)

    description = (
        f"**Appellant:** {appellant.mention} ({appellant})\n"
        f"**User ID:** `{appellant.id}`\n\n"
        f"**Reviewed By:** {reviewer.mention} ({reviewer})\n"
        f"**Reviewer ID:** `{reviewer.id}`\n\n"
        f"**Decision:** {verdict}\n"
    )
    if record.get("reason"):
        description += f"**Original Termination Reason:** {str(record['reason'])[:1000]}\n\n"
    else:
        description += "\n"
    if accepted:
        description += f"**Staff Roles Restored:** {restored_text}\n"
    else:
        description += f"**Denial Reason:** {decision_reason}\n"
    description += (
        f"**Member Notified by DM:** {'Yes' if dm_ok else 'No (their DMs are closed)'}\n\n"
        f"**Date & Time:** <t:{ts}:F> (<t:{ts}:R>)"
    )
    mod_embed = discord.Embed(
        title=f"Termination Appeal {verdict} | Reference {reference}",
        description=description[:4000],
        color=STAFF_COLOR_ACCEPT if accepted else 0xCC3333,
    )
    mod_embed.set_footer(text=f"Moderator: @{reviewer.name} | ID: {appellant.id}")
    mod_ok = await _send_staff_log(guild, MOD_LOG_CHANNEL_ID, mod_embed)
    return staff_ok, mod_ok


async def _accept_appeal(interaction: discord.Interaction, user_id: int, reference: int):
    guild = interaction.guild
    message = interaction.message
    reviewer = interaction.user
    no_mentions = discord.AllowedMentions.none()
    if guild is None or message is None:
        return
    if not _can_manage_staff(reviewer):
        await interaction.response.send_message("You are not authorized to review appeals.", ephemeral=True)
        return
    if message.id in _appeal_busy or not _appeal_is_pending(user_id, reference):
        await interaction.response.send_message("This appeal has already been reviewed.", ephemeral=True)
        return

    _appeal_busy.add(message.id)
    try:
        record = _termination_record_get(user_id, reference) or {}
        if record.get("guild_id") and int(record["guild_id"]) != guild.id:
            await interaction.response.send_message("This appeal belongs to a different server.", ephemeral=True)
            return
        member = await _find_member(guild, user_id)
        if member is None:
            await interaction.response.send_message(
                "That member is no longer in the server, so I can't restore their roles. You can deny the appeal instead.",
                ephemeral=True,
            )
            return

        # Only the staff roles that this termination removed are restored, and only ones they don't already hold.
        saved_ids = record.get("removed_role_ids")
        has_role_record = saved_ids is not None
        wanted_ids = [int(r) for r in (saved_ids or []) if int(r) in STAFF_ROLE_IDS]
        missing_ids = [rid for rid in wanted_ids if guild.get_role(rid) is None]
        roles = [r for r in (guild.get_role(rid) for rid in wanted_ids) if r is not None and r not in member.roles]

        if roles:
            blocked = [r for r in roles if r >= guild.me.top_role]
            if blocked:
                await interaction.response.send_message(
                    "I can't restore these roles because they are at or above my bot role: "
                    + ", ".join(r.mention for r in blocked)
                    + ". Move my bot role above them in Server Settings > Roles.",
                    ephemeral=True, allowed_mentions=no_mentions,
                )
                return
            problem = _bot_cannot_edit(guild, member)
            if problem:
                await interaction.response.send_message(problem, ephemeral=True, allowed_mentions=no_mentions)
                return
            # Same rule as /terminate: you can only act on staff ranked below you (the server owner can act on anyone).
            if guild.owner_id != reviewer.id:
                reviewer_index = _hire_invoker_index(reviewer)
                rank_indexes = [HIRE_RANK_INDEX[r.id] for r in roles if r.id in HIRE_RANK_INDEX]
                if rank_indexes and reviewer_index is not None and min(rank_indexes) <= reviewer_index:
                    await interaction.response.send_message(
                        "You can only accept appeals for staff members who were ranked below you.", ephemeral=True
                    )
                    return

        await interaction.response.defer()
        if roles:
            try:
                await member.add_roles(
                    *roles, reason=f"Termination appeal accepted by {reviewer} ({reviewer.id})"
                )
            except discord.HTTPException as exc:
                await interaction.followup.send(f"I couldn't restore their roles: `{exc}`", ephemeral=True)
                return

        _appeal_set_decision(user_id, reference, "accepted", reviewer.id)

        if roles:
            restored_text = _fmt_roles(roles)
            dm_text = (
                f"Your appeal against your staff termination in **{guild.name}** has been accepted. "
                "Your staff roles have been restored."
            )
        elif has_role_record:
            restored_text = "None (they already held all of their staff roles)"
            dm_text = (
                f"Your appeal against your staff termination in **{guild.name}** has been accepted. "
                "Your staff roles were already in place."
            )
        else:
            restored_text = "None (no role record was saved for this termination; roles must be restored manually)"
            dm_text = (
                f"Your appeal against your staff termination in **{guild.name}** has been accepted. "
                "A member of management will contact you about restoring your staff roles."
            )
        dm_embed = _staff_dm_embed(guild, "Termination Appeal Accepted", dm_text, STAFF_COLOR_ACCEPT)
        if roles:
            dm_embed.add_field(name="Staff Roles Restored", value=", ".join(r.name for r in roles)[:1024], inline=False)
        dm_embed.add_field(name="Reference ID", value=f"`{reference}`", inline=False)
        dm_ok = await _dm_member(member, dm_embed)

        extras = [
            ("Reviewed By", f"{reviewer.mention}\n`{reviewer.id}`", True),
            ("DM Sent", _dm_status(dm_ok), True),
            ("Staff Roles Restored", restored_text, False),
        ]
        if missing_ids:
            extras.append(("Roles No Longer Existing", ", ".join(f"`{rid}`" for rid in missing_ids), False))
        embed = _close_appeal_embed(message.embeds[0], "Termination Appeal Accepted", STAFF_COLOR_ACCEPT, "Accepted", extras)
        await interaction.edit_original_response(embed=embed, view=None)

        staff_ok, mod_ok = await _log_appeal_decision(
            guild, member, reviewer, reference, record, True, None, restored_text, dm_ok
        )
        notes = []
        if not dm_ok:
            notes.append("I could not DM them (their DMs are closed).")
        if not (staff_ok and mod_ok):
            notes.append("I could not post this decision to every log channel. Check my permissions there.")
        if notes:
            await interaction.followup.send("Appeal accepted. " + " ".join(notes), ephemeral=True)
    finally:
        _appeal_busy.discard(message.id)


class StaffAppealDenyModal(discord.ui.Modal, title="Deny Appeal"):
    reason = discord.ui.TextInput(
        label="Reason for denial",
        style=discord.TextStyle.paragraph,
        placeholder="This reason will be sent to the member.",
        max_length=1000,
        required=True,
    )

    def __init__(self, user_id: int, reference: int, message: discord.Message):
        super().__init__()
        self.user_id = user_id
        self.reference = reference
        self.message = message

    async def on_submit(self, interaction: discord.Interaction):
        guild = interaction.guild
        message = self.message
        reviewer = interaction.user
        if guild is None:
            return
        if not _can_manage_staff(reviewer):
            await interaction.response.send_message("You are not authorized to review appeals.", ephemeral=True)
            return
        if message.id in _appeal_busy or not _appeal_is_pending(self.user_id, self.reference):
            await interaction.response.send_message("This appeal has already been reviewed.", ephemeral=True)
            return

        _appeal_busy.add(message.id)
        try:
            await interaction.response.defer(ephemeral=True)
            reason = str(self.reason.value)
            record = _termination_record_get(self.user_id, self.reference) or {}
            _appeal_set_decision(self.user_id, self.reference, "denied", reviewer.id, reason)

            user = await _find_member(guild, self.user_id)
            if user is None:
                try:
                    user = await bot.fetch_user(self.user_id)
                except discord.HTTPException:
                    user = None
            dm_ok = False
            if user is not None:
                dm_embed = _staff_dm_embed(
                    guild,
                    "Termination Appeal Denied",
                    f"Your appeal against your staff termination in **{guild.name}** has been denied. "
                    "The termination remains in effect.",
                    STAFF_COLOR_TERMINATE,
                )
                dm_embed.add_field(name="Reason", value=reason, inline=False)
                dm_embed.add_field(name="Reference ID", value=f"`{self.reference}`", inline=False)
                dm_ok = await _dm_member(user, dm_embed)

            embed = _close_appeal_embed(
                message.embeds[0], "Termination Appeal Denied", STAFF_COLOR_TERMINATE, "Denied",
                [
                    ("Reviewed By", f"{reviewer.mention}\n`{reviewer.id}`", True),
                    ("DM Sent", _dm_status(dm_ok), True),
                    ("Denial Reason", reason, False),
                ],
            )
            try:
                await message.edit(embed=embed, view=None)
            except discord.HTTPException as exc:
                print(f"[appeal] Could not update the appeal message {message.id}: {exc!r}")

            staff_ok, mod_ok = await _log_appeal_decision(
                guild, user or _UnknownUser(self.user_id, guild), reviewer, self.reference, record, False, reason, "", dm_ok
            )
            notes = []
            if not dm_ok:
                notes.append("I could not DM them (their DMs are closed).")
            if not (staff_ok and mod_ok):
                notes.append("I could not post this decision to every log channel. Check my permissions there.")
            await interaction.followup.send("Appeal denied. " + " ".join(notes), ephemeral=True)
        finally:
            _appeal_busy.discard(message.id)

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        print(f"[appeal] Deny modal error: {error!r}")
        traceback.print_exception(type(error), error, error.__traceback__)
        msg = "Something went wrong while denying this appeal."
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)


class StaffAppealAcceptButton(discord.ui.DynamicItem[discord.ui.Button], template=r"staff_appeal_review:accept:(?P<user_id>\d+):(?P<reference>\d+)"):
    """Persistent: the appellant and termination reference live in the custom_id, so it works after restarts."""

    def __init__(self, user_id: int, reference: int):
        super().__init__(discord.ui.Button(
            label="Accept Appeal",
            style=discord.ButtonStyle.success,
            custom_id=f"staff_appeal_review:accept:{user_id}:{reference}",
        ))
        self.user_id = user_id
        self.reference = reference

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button, match, /):
        return cls(int(match["user_id"]), int(match["reference"]))

    async def callback(self, interaction: discord.Interaction):
        await _accept_appeal(interaction, self.user_id, self.reference)


class StaffAppealDenyButton(discord.ui.DynamicItem[discord.ui.Button], template=r"staff_appeal_review:deny:(?P<user_id>\d+):(?P<reference>\d+)"):
    def __init__(self, user_id: int, reference: int):
        super().__init__(discord.ui.Button(
            label="Deny Appeal",
            style=discord.ButtonStyle.danger,
            custom_id=f"staff_appeal_review:deny:{user_id}:{reference}",
        ))
        self.user_id = user_id
        self.reference = reference

    @classmethod
    async def from_custom_id(cls, interaction: discord.Interaction, item: discord.ui.Button, match, /):
        return cls(int(match["user_id"]), int(match["reference"]))

    async def callback(self, interaction: discord.Interaction):
        if not _can_manage_staff(interaction.user):
            await interaction.response.send_message("You are not authorized to review appeals.", ephemeral=True)
            return
        if interaction.message.id in _appeal_busy or not _appeal_is_pending(self.user_id, self.reference):
            await interaction.response.send_message("This appeal has already been reviewed.", ephemeral=True)
            return
        await interaction.response.send_modal(StaffAppealDenyModal(self.user_id, self.reference, interaction.message))


# =====================================================================
# --- WELCOME MESSAGES & LIVE MEMBER COUNT ---
# =====================================================================
import time
import aiohttp
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# ---- Welcome message settings ----
WELCOME_CHANNEL_ID = 1532519492519858347   # channel the welcome message is posted in
WELCOME_SERVER_NAME = "Greenville Roleplay Genesis"
WELCOME_STARTUP_CHANNEL_ID = 1532938753901858966   # #startup-1
WELCOME_VERIFY_CHANNEL_ID = 1533960257615691816    # #verify
WELCOME_BANNER_NAME = "welcome_banner.png"         # local copy kept next to the bot file (see note below)
WELCOME_BANNER_URL = "https://media.discordapp.net/attachments/1534314921322614859/1535794712093532180/gvrg_welcoem.png?ex=6ada9ec9&is=6ad94d49&hm=671c49256fc8412d8aa3970f2aff918358de375075577fc682d48f69ec9b1acc&format=webp&quality=lossless&width=1280&height=427&"
# NOTE: Discord CDN links are signed and expire (this one around Oct 22, 2026). The bot saves a local copy of the
# banner the first time it starts while the link still works. To be safe, you can also drop your own image
# next to this file named welcome_banner.png and it will be used instead of the link.

# ---- Live member count (voice channel) settings ----
MEMBER_COUNT_CATEGORY_ID = 1554667456734167051   # Server Stats category; the bot creates the count channel here if needed
MEMBER_COUNT_CHANNEL_ID = None     # Optional: use an existing voice channel instead of letting the bot create one.
MEMBER_COUNT_NAME_FORMAT = "Total Members • {count}"   # {count} is replaced with the member total.
MEMBER_COUNT_DATA_FILE = "member_count_data.json"   # remembers the channel the bot created
MEMBER_COUNT_DEBOUNCE_SECONDS = 3


# --- shared member count helpers (used by /membercount, -memcount and the voice channel) ---

def guild_member_total(guild: discord.Guild) -> int:
    count = guild.member_count
    return count if count is not None else len(guild.members)


class MemberCountView(discord.ui.LayoutView):
    """Public member count card (Components V2 container, no accent color = no sidebar)."""

    def __init__(self, guild: discord.Guild):
        super().__init__(timeout=None)
        container = discord.ui.Container()
        container.add_item(discord.ui.TextDisplay(
            f"### Member Count\n**{guild_member_total(guild):,}** members in {guild.name}"
        ))
        self.add_item(container)


@bot.tree.command(name="membercount", description="Show the current number of members in the server.")
@app_commands.guild_only()
async def membercount_command(interaction: discord.Interaction):
    # Not ephemeral: everyone in the channel can see the result.
    await interaction.response.send_message(view=MemberCountView(interaction.guild))


@bot.command(name="memcount")
@commands.guild_only()
async def memcount_command(ctx: commands.Context):
    """Show the current number of members in the server. Usage: -memcount"""
    await ctx.send(view=MemberCountView(ctx.guild))


# --- welcome message ---

def _welcome_banner_path() -> Path:
    return Path(__file__).resolve().parent / WELCOME_BANNER_NAME


async def cache_welcome_banner():
    """Save the banner next to the bot once, so the welcome message keeps working after the CDN link expires."""
    path = _welcome_banner_path()
    if path.exists() or not WELCOME_BANNER_URL:
        return
    try:
        # Drop the resize/format params so we save the original image, not a re-encoded copy.
        parts = urlsplit(WELCOME_BANNER_URL)
        keep = [(k, v) for k, v in parse_qsl(parts.query) if k in ("ex", "is", "hm")]
        original_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(keep), ""))
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(original_url) as resp:
                if resp.status != 200:
                    print(f"[welcome] Banner download failed (HTTP {resp.status}); will use the link directly.")
                    return
                data = await resp.read()
        path.write_bytes(data)
        print(f"[welcome] Saved banner to {path.name}.")
    except Exception as exc:
        print(f"[welcome] Could not cache banner: {exc!r}")


class WelcomeView(discord.ui.LayoutView):
    """Welcome card: a mention above a no-sidebar Components V2 container."""

    def __init__(self, member: discord.Member, banner_ref: str = None):
        super().__init__(timeout=None)
        self.add_item(discord.ui.TextDisplay(member.mention))

        container = discord.ui.Container()  # accent_color intentionally unset = no sidebar
        container.add_item(discord.ui.TextDisplay(
            f"## Welcome to {WELCOME_SERVER_NAME}!\n"
            f"Welcome to {WELCOME_SERVER_NAME}! Start by verifying in "
            f"<#{WELCOME_VERIFY_CHANNEL_ID}> if not verified already!\n\n"
            f"See if there is any session's being currently hosted in "
            f"<#{WELCOME_STARTUP_CHANNEL_ID}>! Enjoy!"
        ))
        if banner_ref:
            gallery = discord.ui.MediaGallery()
            gallery.add_item(media=banner_ref)
            container.add_item(gallery)
        container.add_item(discord.ui.TextDisplay("-# Property of GVRG. Enjoy your time here!"))
        self.add_item(container)


async def send_welcome_message(member: discord.Member):
    if WELCOME_CHANNEL_ID is None:
        print("[welcome] WELCOME_CHANNEL_ID is not set, so no welcome message was sent.")
        return
    channel = member.guild.get_channel(WELCOME_CHANNEL_ID)
    if channel is None:
        return  # the configured channel belongs to a different server
    banner_path = _welcome_banner_path()
    try:
        kwargs = {"allowed_mentions": discord.AllowedMentions(users=[member], roles=False, everyone=False)}
        if banner_path.exists():
            kwargs["file"] = discord.File(banner_path, filename=WELCOME_BANNER_NAME)
            kwargs["view"] = WelcomeView(member, f"attachment://{WELCOME_BANNER_NAME}")
        else:
            kwargs["view"] = WelcomeView(member, WELCOME_BANNER_URL or None)
        await channel.send(**kwargs)
    except discord.HTTPException as exc:
        print(f"[welcome] Could not send welcome message for {member} ({member.id}): {exc!r}")


# --- live member count voice channel ---

_mc_state = {"dirty": False, "worker": None, "edits": [], "lock": None}


def _member_count_name(guild: discord.Guild) -> str:
    return MEMBER_COUNT_NAME_FORMAT.format(count=f"{guild_member_total(guild):,}")[:100]


def _member_count_configured() -> bool:
    return bool(MEMBER_COUNT_CHANNEL_ID or MEMBER_COUNT_CATEGORY_ID)


async def _locked_overwrites(guild: discord.Guild) -> dict:
    return {
        # Everyone can see the channel but can't connect to it.
        guild.default_role: discord.PermissionOverwrite(view_channel=True, connect=False),
        guild.me: discord.PermissionOverwrite(view_channel=True, connect=True, manage_channels=True),
    }


async def _get_member_count_channel(guild: discord.Guild):
    """Find (or create, when a category is configured) the locked member count voice channel for this guild."""
    saved = load_json(MEMBER_COUNT_DATA_FILE, {})
    channel_id = MEMBER_COUNT_CHANNEL_ID or saved.get(str(guild.id))
    channel = guild.get_channel(int(channel_id)) if channel_id else None
    if isinstance(channel, discord.VoiceChannel):
        return channel

    if MEMBER_COUNT_CHANNEL_ID or not MEMBER_COUNT_CATEGORY_ID:
        return None
    category = guild.get_channel(MEMBER_COUNT_CATEGORY_ID)
    if not isinstance(category, discord.CategoryChannel):
        return None  # category belongs to a different server (or is wrong)

    channel = await guild.create_voice_channel(
        name=_member_count_name(guild),
        category=category,
        overwrites=await _locked_overwrites(guild),
        reason="Live member count channel",
    )
    try:
        await channel.move(beginning=True, category=category)
    except discord.HTTPException:
        pass
    saved[str(guild.id)] = channel.id
    save_json(MEMBER_COUNT_DATA_FILE, saved)
    print(f"[membercount] Created member count channel {channel.id} in {guild.name}.")
    return channel


async def _ensure_member_count_locked(guild: discord.Guild, channel: discord.VoiceChannel):
    current = channel.overwrites_for(guild.default_role)
    if current.connect is False:
        return
    current.connect = False
    try:
        await channel.set_permissions(guild.default_role, overwrite=current, reason="Lock member count channel")
    except discord.HTTPException as exc:
        print(f"[membercount] Could not lock {channel.id}: {exc!r}")


async def update_member_count_channel(guild: discord.Guild):
    """Make the voice channel's name match the current member total (respects Discord's rename rate limit)."""
    if not _member_count_configured():
        return
    if _mc_state["lock"] is None:
        _mc_state["lock"] = asyncio.Lock()
    async with _mc_state["lock"]:
        channel = await _get_member_count_channel(guild)
        if channel is None:
            return
        await _ensure_member_count_locked(guild, channel)

        # Discord allows about 2 channel renames per 10 minutes. Wait our turn instead of failing.
        edits = _mc_state["edits"]
        while True:
            now = time.monotonic()
            edits[:] = [t for t in edits if now - t < 610]
            if len(edits) < 2:
                break
            await asyncio.sleep(610 - (now - edits[0]))

        new_name = _member_count_name(guild)  # read the count AFTER waiting so it's never stale
        if channel.name == new_name:
            return
        await channel.edit(name=new_name, reason="Live member count update")
        edits.append(time.monotonic())


async def _member_count_worker(guild: discord.Guild):
    try:
        while _mc_state["dirty"]:
            _mc_state["dirty"] = False
            await asyncio.sleep(MEMBER_COUNT_DEBOUNCE_SECONDS)  # lets a burst of joins collapse into one rename
            try:
                await update_member_count_channel(guild)
            except discord.HTTPException as exc:
                print(f"[membercount] Update failed: {exc!r}")
    finally:
        _mc_state["worker"] = None


def schedule_member_count_update(guild: discord.Guild):
    if not _member_count_configured():
        return
    _mc_state["dirty"] = True
    worker = _mc_state["worker"]
    if worker is None or worker.done():
        _mc_state["worker"] = asyncio.create_task(_member_count_worker(guild))


@tasks.loop(minutes=10)
async def member_count_sweep():
    """Safety net: creates the channel on first run and corrects any drift."""
    for guild in bot.guilds:
        try:
            await update_member_count_channel(guild)
        except Exception as exc:
            print(f"[membercount] Sweep failed for {guild.name}: {exc!r}")


@bot.event
async def on_member_join(member: discord.Member):
    schedule_member_count_update(member.guild)
    if not member.bot:
        await send_welcome_message(member)


@bot.event
async def on_member_remove(member: discord.Member):
    schedule_member_count_update(member.guild)


# --- ECONOMY SYSTEM ---

def get_user_eco(user_id: str):
    eco = load_economy()
    if user_id not in eco:
        eco[user_id] = {
            "wallet": 0,
            "bank": 0,
            "last_work": 0,
            "last_collect": 0
        }
        save_economy(eco)
    return eco[user_id]


@bot.tree.command(name="balance", description="Check your or another member's financial balance.")
@app_commands.describe(user="The member whose balance you want to check (optional)")
async def balance_cmd(interaction: discord.Interaction, user: discord.User = None):
    target_user = user or interaction.user
    user_id = str(target_user.id)
    eco = get_user_eco(user_id)
    wallet = eco["wallet"]
    bank = eco["bank"]
    total = wallet + bank

    embed = discord.Embed(
        title=f"{target_user.name}'s Financial Balance",
        color=0x596744
    )
    embed.add_field(name="Wallet", value=f"${wallet:,}", inline=True)
    embed.add_field(name="Bank", value=f"${bank:,}", inline=True)
    embed.add_field(name="Total Net Worth", value=f"${total:,}", inline=False)
    await interaction.response.send_message(embed=embed)
    await log_economy(
        interaction.guild, "Balance Checked",
        f"**Viewer:** {interaction.user.mention} (`{interaction.user.id}`)\n"
        f"**Target:** {target_user.mention} (`{target_user.id}`)\n"
        f"**Wallet:** ${wallet:,} | **Bank:** ${bank:,}",
        footer=f"Balance | ID: {interaction.user.id}",
    )


@bot.tree.command(name="work", description="Work a shift to earn money.")
async def work_cmd(interaction: discord.Interaction):
    user_id = str(interaction.user.id)
    eco_data = load_economy()
    user_eco = eco_data.get(user_id, {"wallet": 0, "bank": 0, "last_work": 0, "last_collect": 0})

    now = central_now().timestamp()
    cooldown = 600  # 10 minutes

    user_role_ids = [role.id for role in interaction.user.roles]

    if ROLE_NO_COOLDOWN not in user_role_ids and (now - user_eco.get("last_work", 0) < cooldown):
        remaining = int(cooldown - (now - user_eco["last_work"]))
        mins, secs = divmod(remaining, 60)
        await interaction.response.send_message(
            f"You must wait {mins}m {secs}s before working again.", 
            ephemeral=True
        )
        return

    earnings = random.randint(200, 700)
    user_eco["wallet"] = user_eco.get("wallet", 0) + earnings
    user_eco["last_work"] = now
    eco_data[user_id] = user_eco
    save_economy(eco_data)

    await interaction.response.send_message(
        f"You completed your shift and earned ${earnings:,}. Funds have been added to your wallet."
    )
    await log_economy(
        interaction.guild, "Work",
        f"**User:** {interaction.user.mention} (`{interaction.user.id}`)\n"
        f"**Earned:** ${earnings:,}\n**Wallet:** ${user_eco['wallet']:,}",
        footer=f"Work | ID: {interaction.user.id}",
    )


@bot.tree.command(name="collect", description="Collect your role-based paycheck.")
async def collect_cmd(interaction: discord.Interaction):
    user_id = str(interaction.user.id)
    eco_data = load_economy()
    user_eco = eco_data.get(user_id, {"wallet": 0, "bank": 0, "last_work": 0, "last_collect": 0})

    now = central_now().timestamp()
    cooldown = 18000  # 5 hours

    user_role_ids = [role.id for role in interaction.user.roles]

    if ROLE_NO_COOLDOWN not in user_role_ids and (now - user_eco.get("last_collect", 0) < cooldown):
        remaining = int(cooldown - (now - user_eco["last_collect"]))
        hours, remainder = divmod(remaining, 3600)
        mins, _ = divmod(remainder, 60)
        await interaction.response.send_message(
            f"You have already collected your paycheck recently. Please wait {hours}h {mins}m.", 
            ephemeral=True
        )
        return

    role_payout_map = [
        (ROLE_BOOSTER, 5000),
        (ROLE_PUBLIC_SERVICES, 1500),
        (ROLE_DEPT_HEAD, 3500),
        (ROLE_SUPERVISOR, 2500),
        (ROLE_STAFF, 2000),
        (ROLE_VERIFIED_MEMBER, 950),
    ]

    total_salary = 0
    earned_roles_lines = []

    if interaction.user.premium_since is not None and ROLE_BOOSTER not in user_role_ids:
        total_salary += 5000
        earned_roles_lines.append(f"<@&{ROLE_BOOSTER}>\n**$5,000**")

    for role_id, payout in role_payout_map:
        if role_id in user_role_ids:
            total_salary += payout
            earned_roles_lines.append(f"<@&{role_id}>\n**${payout:,}**")

    if total_salary == 0:
        await interaction.response.send_message(
            "You do not possess any roles eligible for a paycheck.",
            ephemeral=True
        )
        return

    user_eco["wallet"] = user_eco.get("wallet", 0) + total_salary
    user_eco["last_collect"] = now
    eco_data[user_id] = user_eco
    save_economy(eco_data)

    pay_rates_text = "\n\n".join(earned_roles_lines)

    embed = discord.Embed(
        title="Paycheck Collected",
        description=f"You successfully collected **${total_salary:,}** into your wallet.\n\n**Server Role Pay Rates:**\n\n{pay_rates_text}",
        color=0x596744
    )
    embed.set_footer(text=f"Requested by @{interaction.user.name}")

    await interaction.response.send_message(embed=embed)
    await log_economy(
        interaction.guild, "Paycheck Collected",
        f"**User:** {interaction.user.mention} (`{interaction.user.id}`)\n"
        f"**Amount:** ${total_salary:,}\n**Wallet:** ${user_eco['wallet']:,}",
        footer=f"Collect | ID: {interaction.user.id}",
    )


@bot.tree.command(name="deposit", description="Deposit cash from your wallet into your bank.")
@app_commands.describe(amount="Amount to deposit or 'all'")
async def deposit_cmd(interaction: discord.Interaction, amount: str):
    user_id = str(interaction.user.id)
    eco_data = load_economy()
    user_eco = eco_data.get(user_id, {"wallet": 0, "bank": 0, "last_work": 0, "last_collect": 0})

    wallet = user_eco.get("wallet", 0)
    if wallet <= 0:
        await interaction.response.send_message("You do not have any cash in your wallet to deposit.", ephemeral=True)
        return

    if amount.lower() == "all":
        deposit_amount = wallet
    else:
        try:
            deposit_amount = int(amount)
            if deposit_amount <= 0:
                raise ValueError
        except ValueError:
            await interaction.response.send_message("Please enter a valid positive number or 'all'.", ephemeral=True)
            return

    if deposit_amount > wallet:
        await interaction.response.send_message("You do not have that much cash in your wallet.", ephemeral=True)
        return

    user_eco["wallet"] -= deposit_amount
    user_eco["bank"] += deposit_amount
    eco_data[user_id] = user_eco
    save_economy(eco_data)

    await interaction.response.send_message(f"Deposited ${deposit_amount:,} into your bank account.")
    await log_economy(
        interaction.guild, "Deposit",
        f"**User:** {interaction.user.mention} (`{interaction.user.id}`)\n"
        f"**Amount:** ${deposit_amount:,}\n**Wallet:** ${user_eco['wallet']:,} | **Bank:** ${user_eco['bank']:,}",
        footer=f"Deposit | ID: {interaction.user.id}",
    )


@bot.tree.command(name="withdraw", description="Withdraw cash from your bank into your wallet.")
@app_commands.describe(amount="Amount to withdraw or 'all'")
async def withdraw_cmd(interaction: discord.Interaction, amount: str):
    user_id = str(interaction.user.id)
    eco_data = load_economy()
    user_eco = eco_data.get(user_id, {"wallet": 0, "bank": 0, "last_work": 0, "last_collect": 0})

    bank = user_eco.get("bank", 0)
    if bank <= 0:
        await interaction.response.send_message("You do not have any funds in your bank account to withdraw.", ephemeral=True)
        return

    if amount.lower() == "all":
        withdraw_amount = bank
    else:
        try:
            withdraw_amount = int(amount)
            if withdraw_amount <= 0:
                raise ValueError
        except ValueError:
            await interaction.response.send_message("Please enter a valid positive number or 'all'.", ephemeral=True)
            return

    if withdraw_amount > bank:
        await interaction.response.send_message("You do not have that much money in your bank account.", ephemeral=True)
        return

    user_eco["bank"] -= withdraw_amount
    user_eco["wallet"] += withdraw_amount
    eco_data[user_id] = user_eco
    save_economy(eco_data)

    await interaction.response.send_message(f"Withdrew ${withdraw_amount:,} from your bank into your wallet.")
    await log_economy(
        interaction.guild, "Withdraw",
        f"**User:** {interaction.user.mention} (`{interaction.user.id}`)\n"
        f"**Amount:** ${withdraw_amount:,}\n**Wallet:** ${user_eco['wallet']:,} | **Bank:** ${user_eco['bank']:,}",
        footer=f"Withdraw | ID: {interaction.user.id}",
    )


@bot.tree.command(name="pay", description="Transfer cash from your wallet to another member.")
@app_commands.describe(user="The member to send money to", amount="The amount of money to transfer")
async def pay_cmd(interaction: discord.Interaction, user: discord.User, amount: int):
    if user.bot:
        await interaction.response.send_message("You cannot transfer money to a bot.", ephemeral=True)
        return

    if user.id == interaction.user.id:
        await interaction.response.send_message("You cannot transfer money to yourself.", ephemeral=True)
        return

    if amount <= 0:
        await interaction.response.send_message("Please specify a valid amount greater than 0.", ephemeral=True)
        return

    sender_id = str(interaction.user.id)
    recipient_id = str(user.id)

    eco_data = load_economy()
    sender_eco = eco_data.get(sender_id, {"wallet": 0, "bank": 0, "last_work": 0, "last_collect": 0})

    if sender_eco.get("wallet", 0) < amount:
        await interaction.response.send_message(
            f"You do not have enough cash in your wallet (${sender_eco.get('wallet', 0):,}) to transfer ${amount:,}.", 
            ephemeral=True
        )
        return

    recipient_eco = eco_data.get(recipient_id, {"wallet": 0, "bank": 0, "last_work": 0, "last_collect": 0})

    sender_eco["wallet"] -= amount
    recipient_eco["wallet"] = recipient_eco.get("wallet", 0) + amount

    eco_data[sender_id] = sender_eco
    eco_data[recipient_id] = recipient_eco
    save_economy(eco_data)

    unix_time = int(central_now().timestamp())

    await send_v2_dm(
        bot=interaction.client,
        user=user,
        title="Direct Funds Received",
        body_text=f"You have received a financial transfer from **@{interaction.user.name}** in **{interaction.guild.name}**.\n<t:{unix_time}:F>",
        inner_sections=[f"**Amount Received:** ${amount:,}\n**Transferred To:** Wallet"]
    )

    await interaction.response.send_message(
        f"Successfully sent ${amount:,} to <@{user.id}> from your wallet."
    )
    await log_economy(
        interaction.guild, "Payment",
        f"**From:** {interaction.user.mention} (`{interaction.user.id}`)\n"
        f"**To:** {user.mention} (`{user.id}`)\n**Amount:** ${amount:,}",
        footer=f"Pay | ID: {interaction.user.id}",
    )


@bot.tree.command(name="add-money", description="Add funds directly to a user's balance.")
@app_commands.describe(
    user="The target user", 
    amount="Amount to add", 
    account_type="Target balance account"
)
@app_commands.choices(
    account_type=[
        app_commands.Choice(name="Wallet", value="wallet"),
        app_commands.Choice(name="Bank", value="bank"),
    ]
)
async def add_money_cmd(interaction: discord.Interaction, user: discord.User, amount: int, account_type: app_commands.Choice[str]):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("You do not have permission to manage funds.", ephemeral=True)
        return

    if amount <= 0:
        await interaction.response.send_message("Please enter a valid amount greater than 0.", ephemeral=True)
        return

    target_id = str(user.id)
    eco_data = load_economy()
    target_eco = eco_data.get(target_id, {"wallet": 0, "bank": 0, "last_work": 0, "last_collect": 0})

    target_account = account_type.value
    target_eco[target_account] = target_eco.get(target_account, 0) + amount
    eco_data[target_id] = target_eco
    save_economy(eco_data)

    await interaction.response.send_message(
        f"Successfully added ${amount:,} to <@{user.id}>'s {target_account}."
    )
    await log_economy(
        interaction.guild, "Funds Added (Admin)",
        f"**Target:** {user.mention} (`{user.id}`)\n**Account:** {target_account.capitalize()}\n"
        f"**Amount:** ${amount:,}\n**Added By:** {interaction.user.mention}",
        color=0x3366CC,
        footer=f"Add Money | Staff ID: {interaction.user.id}",
    )


@bot.tree.command(name="remove-balance", description="Deduct funds directly from a user's balance.")
@app_commands.describe(
    user="The target user", 
    amount="Amount to remove", 
    account_type="Target balance account"
)
@app_commands.choices(
    account_type=[
        app_commands.Choice(name="Wallet", value="wallet"),
        app_commands.Choice(name="Bank", value="bank"),
    ]
)
async def remove_balance_cmd(interaction: discord.Interaction, user: discord.User, amount: int, account_type: app_commands.Choice[str]):
    if not interaction.user.guild_permissions.manage_guild:
        await interaction.response.send_message("You do not have permission to remove funds.", ephemeral=True)
        return

    if amount <= 0:
        await interaction.response.send_message("Please enter a valid amount greater than 0.", ephemeral=True)
        return

    target_id = str(user.id)
    eco_data = load_economy()
    target_eco = eco_data.get(target_id, {"wallet": 0, "bank": 0, "last_work": 0, "last_collect": 0})

    target_account = account_type.value
    current_bal = target_eco.get(target_account, 0)
    
    new_bal = max(0, current_bal - amount)
    deducted_amount = current_bal - new_bal
    
    target_eco[target_account] = new_bal
    eco_data[target_id] = target_eco
    save_economy(eco_data)

    await interaction.response.send_message(
        f"Successfully removed **${deducted_amount:,}** from <@{user.id}>'s {target_account}. (New {target_account.capitalize()} Balance: ${new_bal:,})"
    )
    await log_economy(
        interaction.guild, "Funds Removed (Admin)",
        f"**Target:** {user.mention} (`{user.id}`)\n**Account:** {target_account.capitalize()}\n"
        f"**Amount Removed:** ${deducted_amount:,}\n**New Balance:** ${new_bal:,}\n"
        f"**Removed By:** {interaction.user.mention}",
        color=0xCC3333,
        footer=f"Remove Balance | Staff ID: {interaction.user.id}",
    )


class LeaderboardView(discord.ui.View):
    def __init__(self, sorted_users, author_id, per_page=10):
        super().__init__(timeout=120)
        self.sorted_users = sorted_users
        self.author_id = author_id
        self.per_page = per_page
        self.current_page = 0
        self.max_pages = max(1, (len(sorted_users) + per_page - 1) // per_page)
        self.update_buttons()

    def update_buttons(self):
        self.prev_button.disabled = self.current_page == 0
        self.next_button.disabled = self.current_page >= self.max_pages - 1

    def create_embed(self, guild):
        start_idx = self.current_page * self.per_page
        end_idx = start_idx + self.per_page
        page_items = self.sorted_users[start_idx:end_idx]

        embed = discord.Embed(
            title="Economy Leaderboard (Highest to Lowest)",
            color=0x3366CC
        )

        if not page_items:
            embed.description = "No economy records found."
            return embed

        description_lines = []
        for rank, (user_id, total_net) in enumerate(page_items, start=start_idx + 1):
            member = guild.get_member(int(user_id))
            user_mention = f"<@{user_id}>" if member else f"User ID `{user_id}`"
            description_lines.append(f"**#{rank}** {user_mention} — **${total_net:,}**")

        embed.description = "\n".join(description_lines)
        embed.set_footer(text=f"Page {self.current_page + 1} of {self.max_pages}")
        return embed

    @discord.ui.button(label="Previous", style=discord.ButtonStyle.secondary, custom_id="prev_page")
    async def prev_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("You cannot control this leaderboard.", ephemeral=True)
            return

        self.current_page -= 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.create_embed(interaction.guild), view=self)

    @discord.ui.button(label="Next", style=discord.ButtonStyle.secondary, custom_id="next_page")
    async def next_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("You cannot control this leaderboard.", ephemeral=True)
            return

        self.current_page += 1
        self.update_buttons()
        await interaction.response.edit_message(embed=self.create_embed(interaction.guild), view=self)


@bot.tree.command(name="leaderboard", description="View economy rankings from highest to lowest balance.")
async def leaderboard_cmd(interaction: discord.Interaction):
    eco_data = load_economy()
    
    user_totals = []
    for user_id, user_info in eco_data.items():
        total_net = user_info.get("wallet", 0) + user_info.get("bank", 0)
        user_totals.append((user_id, total_net))

    user_totals.sort(key=lambda x: x[1], reverse=True)

    view = LeaderboardView(user_totals, author_id=interaction.user.id)
    embed = view.create_embed(interaction.guild)
    
    await interaction.response.send_message(embed=embed, view=view)
    await log_economy(
        interaction.guild, "Leaderboard Viewed",
        f"**User:** {interaction.user.mention} (`{interaction.user.id}`)",
        footer=f"Leaderboard | ID: {interaction.user.id}",
    )


# ============================================================
# --- BLACKJACK (/blackjack, /bj) ---
#
# Bets come out of the player's WALLET and winnings go back to the wallet.
# Rules: 3-deck shoe, dealer stands on all 17s, blackjack pays 3:2,
# push returns the bet, double down on the first two cards only.
# Anti-exploit: one game per player, bet is deducted up front (atomically),
# only the player who started a game can press its buttons, payouts happen once.
# ============================================================

BJ_MIN_BET = 10
BJ_MAX_BET = 1_000_000
BJ_DECKS = 3
BJ_RESHUFFLE_BELOW = 30     # rebuild the shoe when fewer cards than this remain
BJ_TIMEOUT = 120            # seconds of inactivity -> player auto-stands
BJ_SUITS = ["♠️", "♥️", "♦️", "♣️"]
BJ_RANKS = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"]
BJ_GREEN, BJ_RED, BJ_GOLD, BJ_BLURPLE = 0x2ECC71, 0xE74C3C, 0xF1C40F, 0x596744


def bj_state():
    """Per-bot state (stored on the bot so -reload doesn't lose track of live games)."""
    state = getattr(bot, "_bj_state", None)
    if state is None:
        state = {"active": set(), "shoes": {}}
        bot._bj_state = state
    return state


# --- wallet helpers (synchronous load -> modify -> save, so they can't interleave) ---
def eco_get_wallet(user_id: int) -> int:
    return int(load_economy().get(str(user_id), {}).get("wallet", 0))


def eco_try_deduct_wallet(user_id: int, amount: int) -> bool:
    """Subtract from the wallet only if the player can afford it."""
    data = load_economy()
    rec = data.setdefault(str(user_id), {})
    for key, default in (("wallet", 0), ("bank", 0), ("last_work", 0), ("last_collect", 0)):
        rec.setdefault(key, default)
    if rec["wallet"] < amount:
        return False
    rec["wallet"] -= amount
    save_economy(data)
    return True


def eco_add_wallet(user_id: int, amount: int):
    data = load_economy()
    rec = data.setdefault(str(user_id), {})
    for key, default in (("wallet", 0), ("bank", 0), ("last_work", 0), ("last_collect", 0)):
        rec.setdefault(key, default)
    rec["wallet"] += amount
    save_economy(data)


class BJShoe:
    def __init__(self):
        self.cards = []
        self._build()

    def _build(self):
        self.cards = [(r, s) for _ in range(BJ_DECKS) for s in BJ_SUITS for r in BJ_RANKS]
        random.shuffle(self.cards)

    def draw(self):
        if len(self.cards) < BJ_RESHUFFLE_BELOW:
            self._build()
        return self.cards.pop()

    def __len__(self):
        return len(self.cards)


def bj_hand_value(hand) -> int:
    total, aces = 0, 0
    for rank, _ in hand:
        if rank == "A":
            aces += 1
            total += 11
        elif rank in ("J", "Q", "K"):
            total += 10
        else:
            total += int(rank)
    while total > 21 and aces:
        total -= 10
        aces -= 1
    return total


def bj_is_blackjack(hand) -> bool:
    return len(hand) == 2 and bj_hand_value(hand) == 21


def bj_fmt(hand, hide_second=False) -> str:
    if hide_second:
        return f"`{hand[0][0]}`{hand[0][1]}  🂠"
    return "  ".join(f"`{r}`{s}" for r, s in hand)


class BlackjackView(discord.ui.View):
    def __init__(self, user, bet: int, shoe: BJShoe, guild=None):
        super().__init__(timeout=BJ_TIMEOUT)
        self.user, self.bet, self.shoe, self.guild = user, bet, shoe, guild
        self.start_bet = bet
        self.player = [shoe.draw(), shoe.draw()]
        self.dealer = [shoe.draw(), shoe.draw()]
        self.finished = False
        self.lock = asyncio.Lock()
        self.message = None
        self.result_text = ""
        self.color = BJ_BLURPLE

    # ---------- display ----------
    def make_embed(self) -> discord.Embed:
        reveal = self.finished
        embed = discord.Embed(color=self.color)
        embed.set_author(name=self.user.display_name, icon_url=self.user.display_avatar.url)
        embed.add_field(name="Your Hand", value=bj_fmt(self.player), inline=True)
        embed.add_field(name="Dealer Hand", value=bj_fmt(self.dealer, hide_second=not reveal), inline=True)
        dealer_val = bj_hand_value(self.dealer) if reveal else bj_hand_value(self.dealer[:1])
        embed.add_field(
            name="\u200b",
            value=(
                f"**Value:** {bj_hand_value(self.player)}  |  **Dealer:** {dealer_val}\n"
                f"**Bet:** ${self.bet:,}"
            ),
            inline=False,
        )
        if self.result_text:
            embed.add_field(name="Result", value=self.result_text, inline=False)
        embed.set_footer(text=f"Cards remaining: {len(self.shoe)}")
        return embed

    def refresh_buttons(self):
        self.double_btn.disabled = self.finished or len(self.player) != 2
        if self.finished:
            self.hit_btn.disabled = True
            self.stand_btn.disabled = True
            self.double_btn.disabled = True

    # ---------- game logic ----------
    def dealer_play(self):
        while bj_hand_value(self.dealer) < 17:
            self.dealer.append(self.shoe.draw())

    def resolve_stand(self) -> str:
        self.dealer_play()
        p, d = bj_hand_value(self.player), bj_hand_value(self.dealer)
        if d > 21 or p > d:
            return "win"
        return "push" if p == d else "lose"

    def settle(self, outcome: str):
        """Pay out exactly once. outcome: blackjack | win | push | lose | bust"""
        if self.finished:
            return
        self.finished = True
        self.stop()
        try:
            payout = {
                "blackjack": self.bet + (self.bet * 3) // 2,   # 3:2
                "win": self.bet * 2,
                "push": self.bet,
                "lose": 0,
                "bust": 0,
            }[outcome]
            if payout:
                eco_add_wallet(self.user.id, payout)
            profit = payout - self.bet
            label, self.color = {
                "blackjack": ("🃏 **Blackjack!**", BJ_GOLD),
                "win": ("✅ **You win!**", BJ_GREEN),
                "push": ("🤝 **Push.** Your bet was returned.", BJ_BLURPLE),
                "lose": ("❌ **Dealer wins.**", BJ_RED),
                "bust": ("💥 **Bust!**", BJ_RED),
            }[outcome]
            sign = "+" if profit > 0 else ""
            self.result_text = (
                f"{label}\n{sign}${profit:,}  •  Wallet: **${eco_get_wallet(self.user.id):,}**"
            )
            asyncio.create_task(self.log_result(outcome, profit))
        finally:
            bj_state()["active"].discard(self.user.id)
            self.refresh_buttons()

    async def log_result(self, outcome: str, profit: int):
        names = {"blackjack": "Blackjack", "win": "Win", "push": "Push", "lose": "Loss", "bust": "Bust"}
        sign = "+" if profit > 0 else ""
        await log_economy(
            self.guild, f"Blackjack | {names[outcome]}",
            f"**Player:** {self.user.mention} (`{self.user.id}`)\n"
            f"**Bet:** ${self.bet:,}{' (doubled)' if self.bet != self.start_bet else ''}\n"
            f"**Result:** {sign}${profit:,}\n"
            f"**Wallet:** ${eco_get_wallet(self.user.id):,}",
            color=BJ_GREEN if profit > 0 else (BJ_RED if profit < 0 else BJ_BLURPLE),
            footer=f"Blackjack | ID: {self.user.id}",
        )

    # ---------- plumbing ----------
    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.user.id:
            await interaction.response.send_message("This isn't your game.", ephemeral=True)
            return False
        return True

    async def on_timeout(self):
        async with self.lock:
            if self.finished:
                return
            self.settle(self.resolve_stand())
            if self.message:
                try:
                    await self.message.edit(embed=self.make_embed(), view=self)
                except discord.HTTPException:
                    pass

    async def on_error(self, interaction, error, item):
        # Never leave a player locked out (or a bet stuck) if something unexpected breaks.
        print(f"Blackjack error: {error!r}")
        traceback.print_exception(type(error), error, error.__traceback__)
        bj_state()["active"].discard(self.user.id)

    async def push_update(self, interaction: discord.Interaction):
        self.refresh_buttons()
        await interaction.response.edit_message(embed=self.make_embed(), view=self)

    # ---------- buttons ----------
    @discord.ui.button(label="Hit", style=discord.ButtonStyle.primary)
    async def hit_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        async with self.lock:
            if self.finished:
                return await interaction.response.defer()
            self.player.append(self.shoe.draw())
            value = bj_hand_value(self.player)
            if value > 21:
                self.settle("bust")
            elif value == 21:
                self.settle(self.resolve_stand())
            await self.push_update(interaction)

    @discord.ui.button(label="Stand", style=discord.ButtonStyle.success)
    async def stand_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        async with self.lock:
            if self.finished:
                return await interaction.response.defer()
            self.settle(self.resolve_stand())
            await self.push_update(interaction)

    @discord.ui.button(label="Double Down", style=discord.ButtonStyle.secondary)
    async def double_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        async with self.lock:
            if self.finished:
                return await interaction.response.defer()
            if len(self.player) != 2:
                return await interaction.response.send_message(
                    "You can only double down on your first two cards.", ephemeral=True)
            if not eco_try_deduct_wallet(self.user.id, self.bet):
                return await interaction.response.send_message(
                    "You don't have enough in your wallet to double down.", ephemeral=True)
            self.bet *= 2
            asyncio.create_task(log_economy(
                self.guild, "Blackjack | Double Down",
                f"**Player:** {self.user.mention} (`{self.user.id}`)\n"
                f"**New Bet:** ${self.bet:,}\n**Wallet:** ${eco_get_wallet(self.user.id):,}",
                footer=f"Blackjack Double | ID: {self.user.id}",
            ))
            self.player.append(self.shoe.draw())
            self.settle("bust" if bj_hand_value(self.player) > 21 else self.resolve_stand())
            await self.push_update(interaction)

    @discord.ui.button(label="Split", style=discord.ButtonStyle.secondary, disabled=True)
    async def split_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()

    @discord.ui.button(label="Help", emoji="❓", style=discord.ButtonStyle.secondary, row=1)
    async def help_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            "**Blackjack rules**\n"
            "• Get closer to 21 than the dealer without going over.\n"
            "• Number cards = face value, J/Q/K = 10, Ace = 1 or 11.\n"
            "• **Hit** draws a card. **Stand** ends your turn.\n"
            "• **Double Down** doubles your bet, draws one card, then stands (first move only).\n"
            "• The dealer stands on 17. Blackjack pays **3:2**. A tie returns your bet.\n"
            "• Bets are taken from your **wallet**.\n"
            "• If you're idle for 2 minutes you automatically stand.",
            ephemeral=True,
        )


async def blackjack_start(interaction: discord.Interaction, bet: int):
    uid = interaction.user.id
    state = bj_state()

    # Claim the slot BEFORE any await so two fast commands can't both start a game.
    if uid in state["active"]:
        await interaction.response.send_message(
            "You already have a Blackjack game in progress. Finish it first.", ephemeral=True)
        return
    state["active"].add(uid)

    deducted = False
    view = None
    try:
        if not eco_try_deduct_wallet(uid, bet):
            state["active"].discard(uid)
            await interaction.response.send_message(
                f"You don't have enough cash in your wallet. You have **${eco_get_wallet(uid):,}**.",
                ephemeral=True,
            )
            return
        deducted = True
        await log_economy(
            interaction.guild, "Blackjack | Bet Placed",
            f"**Player:** {interaction.user.mention} (`{interaction.user.id}`)\n"
            f"**Bet:** ${bet:,}\n**Wallet:** ${eco_get_wallet(uid):,}",
            footer=f"Blackjack Bet | ID: {uid}",
        )

        shoe = state["shoes"].setdefault(uid, BJShoe())
        view = BlackjackView(interaction.user, bet, shoe, guild=interaction.guild)

        # Naturals end the hand immediately.
        player_bj, dealer_bj = bj_is_blackjack(view.player), bj_is_blackjack(view.dealer)
        if player_bj or dealer_bj:
            outcome = "push" if (player_bj and dealer_bj) else ("blackjack" if player_bj else "lose")
            view.settle(outcome)
            await interaction.response.send_message(embed=view.make_embed())
            return

        view.refresh_buttons()
        await interaction.response.send_message(embed=view.make_embed(), view=view)
        view.message = await interaction.original_response()
    except Exception:
        # Failed before the hand was playable: refund the bet and free the player.
        if deducted and (view is None or not view.finished):
            eco_add_wallet(uid, bet)
        state["active"].discard(uid)
        raise


@bot.tree.command(name="blackjack", description="Play Blackjack against the dealer using your wallet.")
@app_commands.describe(bet="Amount of cash to wager")
async def blackjack_cmd(interaction: discord.Interaction, bet: app_commands.Range[int, BJ_MIN_BET, BJ_MAX_BET]):
    await blackjack_start(interaction, bet)


@bot.tree.command(name="bj", description="Play Blackjack (short for /blackjack).")
@app_commands.describe(bet="Amount of cash to wager")
async def bj_cmd(interaction: discord.Interaction, bet: app_commands.Range[int, BJ_MIN_BET, BJ_MAX_BET]):
    await blackjack_start(interaction, bet)


# ============================================================
# --- SHOP (/shop) ---
#
# The shop is intentionally EMPTY for now. To add an item later, add one entry
# to SHOP_ITEMS, for example:
#
#   SHOP_ITEMS["lucky_charm"] = {
#       "name": "Lucky Charm",
#       "price": 500,
#       "description": "Brings good luck.",
#       "emoji": "🍀",
#   }
#
# Purchase tracking (inventory, limits, cooldowns, one-time items, roles, ...)
# will be implemented in shop_has_purchased / shop_record_purchase once the
# rules are decided. shop_purchase() already handles payment + refund-on-failure
# and is not hooked to a command yet.
# ============================================================

SHOP_DATA_FILE = "shop_data.json"      # reserved for purchase tracking later
SHOP_ITEMS = {}                        # item_id -> {"name", "price", "description", "emoji"}


def load_shop_data():
    return load_json(SHOP_DATA_FILE, {"purchases": {}})


def save_shop_data(data):
    save_json(SHOP_DATA_FILE, data)


def shop_has_purchased(user_id: int, item_id: str) -> bool:
    """TODO: check purchase history once the tracking rules are defined."""
    return False


def shop_record_purchase(user_id: int, item_id: str):
    """TODO: store the purchase once the tracking rules are defined."""
    raise NotImplementedError("Purchase tracking has not been set up yet.")


async def shop_purchase(guild, user_id: int, item_id: str):
    """Skeleton purchase flow. Returns (success, message). Not exposed as a command yet."""
    item = SHOP_ITEMS.get(item_id)
    if item is None:
        return False, "That item doesn't exist."
    price = int(item["price"])
    if not eco_try_deduct_wallet(user_id, price):
        return False, f"You can't afford **{item['name']}** (${price:,})."
    try:
        shop_record_purchase(user_id, item_id)
    except Exception:
        eco_add_wallet(user_id, price)          # refund if recording fails
        raise
    await log_economy(
        guild, "Shop Purchase",
        f"**User:** <@{user_id}>\n**Item:** {item['name']} (`{item_id}`)\n**Price:** ${price:,}",
        footer=f"Shop | ID: {user_id}",
    )
    return True, f"You bought **{item['name']}** for ${price:,}."


@bot.tree.command(name="shop", description="Browse the shop.")
async def shop_cmd(interaction: discord.Interaction):
    embed = discord.Embed(title="Shop", color=0x596744)
    if not SHOP_ITEMS:
        embed.description = "The shop is empty right now. Check back soon!"
    else:
        for item in SHOP_ITEMS.values():
            embed.add_field(
                name=f"{item.get('emoji', '🛒')} {item['name']} — ${int(item['price']):,}",
                value=item.get("description") or "\u200b",
                inline=False,
            )
    await interaction.response.send_message(embed=embed)
    await log_economy(
        interaction.guild, "Shop Viewed",
        f"**User:** {interaction.user.mention} (`{interaction.user.id}`)",
        footer=f"Shop Browse | ID: {interaction.user.id}",
    )


# --- CITATION / WARRANT SYSTEM ---
#
# The citation workflow is intentionally separate from the old citation system.
# /cite creates the official citation/case record.
# /identity lets a civilian view/pay their warrants, license fee, and citations.
# /view-citation lets authorized LEO/staff view another member's record.
# /warrent creates a warrant request from an existing citation case number.

CITATION_DATA_FILE = "citation_data.json"
WARRANT_LOG_CHANNEL_ID = 1556065981917306910
LEO_LOG_CHANNEL_ID = 1535521578643755078
LICENSE_FEE = 500
WARRANT_DUE_DAYS = 7
# LEO roles allowed to approve or deny warrant requests.
WARRANT_REVIEW_ROLE_IDS = {1533941801243770960, 1541653385592315995}


def load_citation_data():
    return load_json(
        CITATION_DATA_FILE,
        {
            "next_case": 1001,
            "citations": {},
            "warrants": {},
            "licenses": {},
        },
    )


def save_citation_data(data):
    save_json(CITATION_DATA_FILE, data)


async def log_citation_event(bot_client, guild, title, description, color=0x596744, footer_text="Citation System"):
    """Send every citation, payment, license, and warrant event to the LEO log."""
    await log_to_channel(
        bot=bot_client,
        guild=guild,
        channel_id=LEO_LOG_CHANNEL_ID,
        title=title,
        description=description,
        color=color,
        footer_text=footer_text,
    )


def parse_fine_amount(value: str):
    """Accept $250, 250, $1,250, etc. and return an integer."""
    cleaned = (value or "").strip().replace("$", "").replace(",", "")
    amount = int(cleaned)
    if amount < 0:
        raise ValueError
    return amount


def get_license_record(data, user_id):
    record = data.setdefault("licenses", {}).setdefault(
        str(user_id),
        {"fee_paid": False, "status": "Valid", "suspended_at": None},
    )
    record.setdefault("fee_paid", False)
    record.setdefault("status", "Valid")
    record.setdefault("suspended_at", None)
    return record


def user_citations(data, user_id):
    return [
        c for c in data.get("citations", {}).values()
        if str(c.get("defendant_id")) == str(user_id)
    ]


def user_warrants(data, user_id):
    return [
        w for w in data.get("warrants", {}).values()
        if str(w.get("defendant_id")) == str(user_id)
    ]


def active_warrants(data, user_id):
    return [
        w for w in user_warrants(data, user_id)
        if w.get("status") == "Active"
    ]


def refresh_license_status(data, user_id):
    record = get_license_record(data, user_id)
    active = active_warrants(data, user_id)
    if active:
        record["status"] = "Suspended"
        if not record.get("suspended_at"):
            record["suspended_at"] = int(central_now().timestamp())
    elif record.get("fee_paid"):
        record["status"] = "Valid"
        record["suspended_at"] = None
    else:
        record["status"] = "License Fee Unpaid"
    return record


def all_warrants_paid(data, user_id):
    return len(active_warrants(data, user_id)) == 0


def all_citations_paid(data, user_id):
    return all(
        c.get("status") == "Paid"
        for c in user_citations(data, user_id)
    )


def citation_case(citation):
    return int(citation.get("case_number", citation.get("citation_id", 0)))


def citation_display(citation, guild):
    defendant = guild.get_member(int(citation["defendant_id"]))
    defendant_text = defendant.mention if defendant else f"<@{citation['defendant_id']}>"
    lines = [
        f"**Case #{citation_case(citation)}**",
        f"**Suspect:** {defendant_text}",
    ]
    if citation.get("location"):
        lines.append(f"**Location:** {citation['location']}")
    if citation.get("vehicle_description"):
        lines.append(f"**Vehicle:** {citation['vehicle_description']}")
    if citation.get("vehicle_plate"):
        lines.append(f"**Plate:** {citation['vehicle_plate']}")
    lines += [
        f"**Penal Code:** {citation.get('penal_code', 'N/A')}",
        f"**Fine:** ${citation.get('fine_amount', 0):,}",
        f"**Vehicle Impound:** {citation.get('impound_status', 'N/A')}",
    ]
    if citation.get("jail_time"):
        lines.append(f"**Jail Time:** {citation['jail_time']}")
    if citation.get("other_officers"):
        lines.append(f"**Other Officers:** {citation['other_officers']}")
    if citation.get("mugshot_url"):
        lines.append(f"**Mugshot:** [View]({citation['mugshot_url']})")
    if citation.get("department"):
        lines.append(f"**Department:** {citation['department']}")
    lines.append(f"**Issuing Officer:** {citation.get('rank_and_name', 'N/A')}")
    if citation.get("signature"):
        lines.append(f"**Signature:** {citation['signature']}")
    lines.append(f"**Status:** {citation.get('status', 'Unpaid')}")
    return "\n".join(lines)


async def send_citation_dm(bot_client, user, citation, guild):
    await send_v2_dm(
        bot=bot_client,
        user=user,
        title=f"Citation Issued | Case #{citation_case(citation)}",
        body_text=(
            f"You have been issued a citation in **{guild.name}**.\n"
            f"Issued by **{citation.get('rank_and_name', 'Unknown Officer')}**."
        ),
        inner_sections=[
            f"**Case Number:** #{citation_case(citation)}",
            f"**Fine:** ${citation.get('fine_amount', 0):,}\n**Status:** {citation.get('status', 'Unpaid')}",
            f"**Penal Code:** {citation.get('penal_code', 'N/A')}\n**Location:** {citation.get('location', 'N/A')}",
            "Use `/identity` in the server to view and pay your citation.",
        ],
    )


async def send_warrant_dm(bot_client, user, warrant, citation, guild):
    await send_v2_dm(
        bot=bot_client,
        user=user,
        title=f"Warrant Issued | Case #{warrant['case_number']}",
        body_text=(
            f"A warrant has been issued to you in **{guild.name}**.\n"
            f"Your license has automatically been suspended."
        ),
        inner_sections=[
            f"**Warrant Case:** #{warrant['warrant_id']}\n**Citation Case:** #{warrant['case_number']}",
            f"**Reason:** {warrant['reason']}",
            "You must pay your active warrant(s) before you can pay your license fee or citations.",
            "Use `/identity` in the server to view your warrant and payment options.",
        ],
    )


CITATION_CHANNEL_ID = 1534060631462907985
CITE_IMPOUND_CHOICES = [
    app_commands.Choice(name="Yes", value="Yes"),
    app_commands.Choice(name="No", value="No"),
]


@bot.tree.command(name="cite", description="Issue a citation to a suspect.")
@app_commands.guild_only()
@app_commands.describe(
    suspect="The member being cited.",
    location="Where the violation happened (e.g. Greenville Dr, near Lakeville).",
    vehicle_description="Vehicle description (e.g. Black, Audi R8).",
    vehicle_plate="Vehicle plate (e.g. JTM-123).",
    penal_code="Penal code(s) violated (e.g. (6)15 Speeding 5-15 MPH).",
    fine_amount="Fine amount - the $ is REQUIRED, any custom number (e.g. $250).",
    vehicle_impound="Was the vehicle impounded?",
    issuing_officer="Your rank and name (e.g. Sheriff, Cleetus Mod).",
    signature="Your signature.",
    jail_time="(Arrest only) Jail time (e.g. 60s).",
    other_officers="(Arrest only) Other responding officers.",
    mugshot="(Arrest only) Mugshot image of the suspect.",
)
@app_commands.choices(vehicle_impound=CITE_IMPOUND_CHOICES)
async def cite_cmd(
    interaction: discord.Interaction,
    suspect: discord.Member,
    location: app_commands.Range[str, 1, 400],
    vehicle_description: app_commands.Range[str, 1, 400],
    vehicle_plate: app_commands.Range[str, 1, 100],
    penal_code: app_commands.Range[str, 1, 1000],
    fine_amount: app_commands.Range[str, 1, 100],
    vehicle_impound: app_commands.Choice[str],
    issuing_officer: app_commands.Range[str, 1, 200],
    signature: app_commands.Range[str, 1, 200],
    jail_time: Optional[app_commands.Range[str, 1, 100]] = None,
    other_officers: Optional[app_commands.Range[str, 1, 500]] = None,
    mugshot: Optional[discord.Attachment] = None,
):
    if interaction.guild is None:
        await interaction.response.send_message("This can only be used inside a server.", ephemeral=True)
        return

    # The "$" is required, followed by any custom whole-dollar number.
    fine_text = fine_amount.strip()
    try:
        if not fine_text.startswith("$"):
            raise ValueError
        fine_value = parse_fine_amount(fine_text)
    except (ValueError, TypeError):
        await interaction.response.send_message(
            "The **$ is required** in the fine amount. Enter a dollar sign followed by a number, "
            "such as `$250` or `$1,250`.",
            ephemeral=True,
        )
        return

    if mugshot is not None and not (mugshot.content_type or "").startswith("image/"):
        await interaction.response.send_message(
            "The mugshot must be an image file (PNG, JPG, etc.).", ephemeral=True
        )
        return

    # Uploading the mugshot can take a moment, so acknowledge right away.
    await interaction.response.defer(ephemeral=True)

    citation_channel = interaction.guild.get_channel(CITATION_CHANNEL_ID)
    if citation_channel is None:
        try:
            citation_channel = await interaction.guild.fetch_channel(CITATION_CHANNEL_ID)
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            citation_channel = None

    data = load_citation_data()
    case_number = int(data.get("next_case", 1001))
    data["next_case"] = case_number + 1
    now = int(central_now().timestamp())
    due_at = now + (WARRANT_DUE_DAYS * 86400)

    citation = {
        "case_number": case_number,
        "defendant_id": int(suspect.id),
        "location": location.strip(),
        "vehicle_description": vehicle_description.strip(),
        "vehicle_plate": vehicle_plate.strip(),
        "penal_code": penal_code.strip(),
        "fine_amount": fine_value,
        "impound_status": vehicle_impound.value,
        "rank_and_name": issuing_officer.strip(),
        "signature": signature.strip(),
        "jail_time": jail_time.strip() if jail_time else None,
        "other_officers": other_officers.strip() if other_officers else None,
        "mugshot_url": None,
        "officer_id": interaction.user.id,
        "issued_at": now,
        "due_at": due_at,
        "status": "Unpaid",
        "warrant_id": None,
    }

    is_arrest = bool(citation["jail_time"] or citation["other_officers"] or mugshot)

    citation_text = (
        f"**Suspect:** {suspect.mention}\n\n"
        f"-----------\n\n"
        f"**Location:** {citation['location']}\n"
        f"**Vehicle Description:** {citation['vehicle_description']}\n"
        f"**Vehicle Plate:** {citation['vehicle_plate']}\n\n"
        f"-----------\n\n"
        f"**Penal Code(s):** {citation['penal_code']}\n"
    )
    if citation["jail_time"]:
        citation_text += f"**Jail Time:** {citation['jail_time']}\n"
    citation_text += (
        f"**Fine:** ${fine_value:,}\n"
        f"**Vehicle Impound:** {citation['impound_status']}\n"
    )
    if citation["other_officers"]:
        citation_text += (
            f"\n-----------\n\n"
            f"**Other Responding Officers:** {citation['other_officers']}\n"
        )
    citation_text += (
        f"\n-----------\n\n"
        f"**Issuing Officer:** {citation['rank_and_name']}\n"
        f"**Signature:** {citation['signature']}"
    )

    if citation_channel is not None:
        try:
            files = [await mugshot.to_file()] if mugshot is not None else []
            sent = await citation_channel.send(content=citation_text, files=files)
            if sent.attachments:
                citation["mugshot_url"] = sent.attachments[0].url
        except (discord.Forbidden, discord.HTTPException):
            citation_channel = None

    data["citations"][str(case_number)] = citation
    save_citation_data(data)

    log_description = (
        f"**Suspect:** {suspect.mention}\n"
        f"**Location:** {citation['location']}\n"
        f"**Vehicle:** {citation['vehicle_description']}\n"
        f"**Plate:** {citation['vehicle_plate']}\n"
        f"**Penal Code:** {citation['penal_code']}\n"
    )
    if is_arrest:
        log_description += f"**Jail Time:** {citation['jail_time'] or 'N/A'}\n"
    log_description += (
        f"**Fine:** ${fine_value:,}\n"
        f"**Vehicle Impound:** {citation['impound_status']}\n"
    )
    if is_arrest:
        log_description += (
            f"**Other Officers:** {citation['other_officers'] or 'None'}\n"
            f"**Mugshot:** {citation['mugshot_url'] or 'None'}\n"
        )
    log_description += (
        f"**Issuing Officer:** {citation['rank_and_name']}\n"
        f"**Signature:** {citation['signature']}\n"
        f"**Issued By:** {interaction.user.mention}\n"
        f"**Payment Due:** <t:{due_at}:F>"
    )
    await log_citation_event(
        interaction.client, interaction.guild,
        f"Citation Issued | Case #{case_number}",
        log_description,
        footer_text=f"Citation Case #{case_number}",
    )

    await send_citation_dm(interaction.client, suspect, citation, interaction.guild)

    if citation_channel is None:
        await interaction.followup.send(
            f"Citation **#{case_number}** was saved, but it could not be posted to the citation channel.",
            ephemeral=True,
        )
        return
    await interaction.followup.send(
        f"Citation issued successfully. Case number: **#{case_number}**", ephemeral=True
    )


# ---------- CITATION PAYMENT / WARRANT VIEWS ----------
class CitationMainSelect(discord.ui.Select):
    def __init__(self, target_user_id: int, staff_view=False):
        self.target_user_id = int(target_user_id)
        self.staff_view = staff_view
        options = [
            discord.SelectOption(label="Warrants", description="View active and past warrants.", value="warrants"),
            discord.SelectOption(label="License", description="View your license and pay the license fee.", value="license"),
            discord.SelectOption(label="Citations", description="View and pay citation fines.", value="citations"),
        ]
        super().__init__(placeholder="Select an option below...", options=options, min_values=1, max_values=1)

    async def callback(self, interaction: discord.Interaction):
        data = load_citation_data()
        refresh_license_status(data, self.target_user_id)
        save_citation_data(data)
        selected = self.values[0]
        if selected == "warrants":
            await show_warrants(interaction, self.target_user_id, self.staff_view)
        elif selected == "license":
            await show_license(interaction, self.target_user_id)
        else:
            await show_citations(interaction, self.target_user_id)


class CitationDashboardView(discord.ui.View):
    def __init__(self, target_user_id: int, staff_view=False):
        super().__init__(timeout=300)
        self.add_item(CitationMainSelect(target_user_id, staff_view=staff_view))


async def show_license(interaction, user_id):
    data = load_citation_data()
    record = refresh_license_status(data, user_id)
    active = active_warrants(data, user_id)
    save_citation_data(data)

    description = (
        f"**License Status:** {record['status']}\n"
        f"**License Fee:** {'Paid' if record.get('fee_paid') else f'Unpaid (${LICENSE_FEE:,})'}\n"
    )
    if active:
        description += f"**Active Warrants:** {len(active)}\nYou must pay all active warrants before paying the license fee."
    elif not record.get("fee_paid"):
        description += "You may pay the license fee now."
    else:
        description += "Your license is current."

    view = discord.ui.View(timeout=300)
    if not active and not record.get("fee_paid"):
        button = discord.ui.Button(label=f"Pay License ${LICENSE_FEE:,}", style=discord.ButtonStyle.success)
        async def pay_license(inter):
            latest = load_citation_data()
            latest_record = refresh_license_status(latest, user_id)
            if active_warrants(latest, user_id):
                await inter.response.send_message("You must pay all active warrants first.", ephemeral=True)
                return
            if latest_record.get("fee_paid"):
                await inter.response.send_message("Your license fee is already paid.", ephemeral=True)
                return
            eco = get_user_eco(str(user_id))
            if eco.get("wallet", 0) < LICENSE_FEE:
                await inter.response.send_message(
                    f"You need ${LICENSE_FEE:,} in your wallet to pay your license fee. You currently have ${eco.get('wallet', 0):,}.",
                    ephemeral=True,
                )
                return
            eco["wallet"] -= LICENSE_FEE
            eco_data = load_economy()
            eco_data[str(user_id)] = eco
            save_economy(eco_data)
            latest_record["fee_paid"] = True
            latest_record["status"] = "Valid"
            latest_record["suspended_at"] = None
            latest_record["paid_at"] = int(central_now().timestamp())
            save_citation_data(latest)
            await log_citation_event(
                inter.client, inter.guild,
                f"License Fee Paid | User {user_id}",
                f"**User:** <@{user_id}>\n**Amount:** ${LICENSE_FEE:,}\n**Paid By:** {inter.user.mention}\n**License Status:** Valid",
                footer_text="Citation / License Payment",
            )
            await log_economy(
                inter.guild, "License Fee Paid",
                f"**User:** <@{user_id}>\n**Amount:** ${LICENSE_FEE:,}\n**Wallet:** ${eco['wallet']:,}",
                footer=f"License Payment | ID: {user_id}",
            )
            await inter.response.send_message("Your license fee has been paid. Your license is now valid.", ephemeral=True)
        button.callback = pay_license
        view.add_item(button)

    await interaction.response.send_message(description, view=view, ephemeral=True)


async def show_citations(interaction, user_id):
    data = load_citation_data()
    record = refresh_license_status(data, user_id)
    citations = sorted(user_citations(data, user_id), key=citation_case, reverse=True)
    active = active_warrants(data, user_id)
    save_citation_data(data)

    if active:
        await interaction.response.send_message(
            "You must pay all active warrants before you can pay your license or citation tickets. Use **Warrants** from the dropdown first.",
            ephemeral=True,
        )
        return
    if not record.get("fee_paid"):
        await interaction.response.send_message(
            f"You must pay your **${LICENSE_FEE:,} license fee** before you can pay citations. Use **License** from the dropdown first.",
            ephemeral=True,
        )
        return

    if not citations:
        await interaction.response.send_message("No citations were found.", ephemeral=True)
        return

    embed = discord.Embed(title="Citation History", color=0x596744)
    for citation in citations[:25]:
        embed.add_field(
            name=f"Case #{citation_case(citation)} — {citation.get('status', 'Unpaid')}",
            value=(
                f"**Fine:** ${citation.get('fine_amount', 0):,}\n"
                f"**Penal Code:** {citation.get('penal_code', 'N/A')}"
            ),
            inline=False,
        )

    view = discord.ui.View(timeout=300)
    unpaid = [c for c in citations if c.get("status") != "Paid"]
    if unpaid:
        select = CitationPaymentSelect(unpaid, user_id)
        view.add_item(select)
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


class CitationPaymentSelect(discord.ui.Select):
    def __init__(self, citations, user_id):
        self.user_id = int(user_id)
        options = [
            discord.SelectOption(
                label=f"Pay Case #{citation_case(c)} — ${c.get('fine_amount', 0):,}",
                value=str(citation_case(c)),
                description=str(c.get("penal_code", "Citation"))[:100],
            )
            for c in citations[:25]
        ]
        super().__init__(placeholder="Select a citation to pay...", options=options)

    async def callback(self, interaction):
        data = load_citation_data()
        if active_warrants(data, self.user_id):
            await interaction.response.send_message("You must pay your warrant(s) first.", ephemeral=True)
            return
        record = refresh_license_status(data, self.user_id)
        if not record.get("fee_paid"):
            await interaction.response.send_message("You must pay your license fee first.", ephemeral=True)
            return
        case_number = self.values[0]
        citation = data.get("citations", {}).get(case_number)
        if not citation or citation.get("status") == "Paid":
            await interaction.response.send_message("That citation is already paid or no longer exists.", ephemeral=True)
            return
        amount = int(citation.get("fine_amount", 0))
        eco = get_user_eco(str(self.user_id))
        if eco.get("wallet", 0) < amount:
            await interaction.response.send_message(
                f"You need ${amount:,} in your wallet to pay this citation. You currently have ${eco.get('wallet', 0):,}.",
                ephemeral=True,
            )
            return
        eco["wallet"] -= amount
        eco_data = load_economy()
        eco_data[str(self.user_id)] = eco
        save_economy(eco_data)
        citation["status"] = "Paid"
        citation["paid_at"] = int(central_now().timestamp())
        save_citation_data(data)
        await log_citation_event(
            interaction.client, interaction.guild,
            f"Citation Paid | Case #{case_number}",
            f"**Defendant:** <@{self.user_id}>\n**Amount:** ${amount:,}\n**Paid By:** {interaction.user.mention}\n**Penal Code:** {citation.get('penal_code', 'N/A')}",
            footer_text=f"Citation Payment | Case #{case_number}",
        )
        await log_economy(
            interaction.guild, f"Citation Paid | Case #{case_number}",
            f"**User:** <@{self.user_id}>\n**Amount:** ${amount:,}\n**Wallet:** ${eco['wallet']:,}",
            footer=f"Citation Payment | ID: {self.user_id}",
        )
        await interaction.response.send_message(
            f"Citation **#{case_number}** has been paid for **${amount:,}**.",
            ephemeral=True,
        )


class WarrantPaymentSelect(discord.ui.Select):
    def __init__(self, warrants, user_id):
        self.user_id = int(user_id)
        options = [
            discord.SelectOption(
                label=f"Pay Warrant #{w.get('warrant_id')} — Citation #{w.get('case_number')}",
                value=str(w.get("warrant_id")),
                description=str(w.get("reason", "Warrant"))[:100],
            )
            for w in warrants[:25]
        ]
        super().__init__(placeholder="Select a warrant to pay...", options=options)

    async def callback(self, interaction):
        data = load_citation_data()
        warrant_id = self.values[0]
        warrant = data.get("warrants", {}).get(warrant_id)
        if not warrant or warrant.get("status") != "Active":
            await interaction.response.send_message("That warrant is already paid or no longer exists.", ephemeral=True)
            return
        if str(warrant.get("defendant_id")) != str(self.user_id):
            await interaction.response.send_message("You cannot pay another user's warrant.", ephemeral=True)
            return
        citation = data.get("citations", {}).get(str(warrant.get("case_number")))
        amount = int(citation.get("fine_amount", 0)) if citation else 0
        eco = get_user_eco(str(self.user_id))
        if eco.get("wallet", 0) < amount:
            await interaction.response.send_message(
                f"You need ${amount:,} in your wallet to pay this warrant. You currently have ${eco.get('wallet', 0):,}.",
                ephemeral=True,
            )
            return
        eco["wallet"] -= amount
        eco_data = load_economy()
        eco_data[str(self.user_id)] = eco
        save_economy(eco_data)
        warrant["status"] = "Paid"
        warrant["paid_at"] = int(central_now().timestamp())
        record = refresh_license_status(data, self.user_id)
        save_citation_data(data)
        await log_citation_event(
            interaction.client, interaction.guild,
            f"Warrant Paid | #{warrant_id}",
            f"**User:** <@{self.user_id}>\n**Warrant:** #{warrant_id}\n**Citation Case:** #{warrant.get('case_number')}\n**Amount:** ${amount:,}\n**Paid By:** {interaction.user.mention}\n**License Status:** {record['status']}",
            footer_text=f"Warrant Payment | #{warrant_id}",
        )
        await log_economy(
            interaction.guild, f"Warrant Paid | #{warrant_id}",
            f"**User:** <@{self.user_id}>\n**Amount:** ${amount:,}\n**Wallet:** ${eco['wallet']:,}",
            footer=f"Warrant Payment | ID: {self.user_id}",
        )
        await interaction.response.send_message(
            f"Warrant **#{warrant_id}** has been paid.\n"
            f"License status: **{record['status']}**.\n"
            "If your license fee is unpaid, pay it before paying citations.",
            ephemeral=True,
        )


async def show_warrants(interaction, user_id, staff_view=False):
    data = load_citation_data()
    warrants = sorted(user_warrants(data, user_id), key=lambda w: int(w.get("warrant_id", 0)), reverse=True)
    active = active_warrants(data, user_id)
    refresh_license_status(data, user_id)
    save_citation_data(data)

    embed = discord.Embed(title="Warrant History", color=0x596744)
    if not warrants:
        embed.description = "No warrants found."
    else:
        for warrant in warrants[:25]:
            served = "Yes" if warrant.get("served") else "No"
            embed.add_field(
                name=f"Warrant #{warrant.get('warrant_id')} — {warrant.get('status', 'Unknown')}",
                value=(
                    f"**Citation Case:** #{warrant.get('case_number')}\n"
                    f"**Reason:** {warrant.get('reason', 'N/A')}\n"
                    f"**Served:** {served}"
                ),
                inline=False,
            )

    view = discord.ui.View(timeout=300)
    if active and not staff_view:
        view.add_item(WarrantPaymentSelect(active, user_id))
    if staff_view and active:
        for warrant in active[:25]:
            button = discord.ui.Button(
                label=f"Warrant #{warrant.get('warrant_id')} Served",
                style=discord.ButtonStyle.success,
            )
            async def served_callback(inter, warrant_id=str(warrant.get("warrant_id"))):
                if not (inter.user.guild_permissions.kick_members or inter.user.guild_permissions.administrator):
                    await inter.response.send_message("You do not have permission to mark warrants as served.", ephemeral=True)
                    return
                latest = load_citation_data()
                target = latest.get("warrants", {}).get(warrant_id)
                if not target:
                    await inter.response.send_message("Warrant not found.", ephemeral=True)
                    return
                target["served"] = True
                target["served_by"] = inter.user.id
                target["served_at"] = int(central_now().timestamp())
                save_citation_data(latest)
                await log_citation_event(
                    inter.client, inter.guild,
                    f"Warrant Served | #{warrant_id}",
                    f"**Defendant:** <@{target.get('defendant_id')}>\n**Citation Case:** #{target.get('case_number')}\n**Served By:** {inter.user.mention}\n**Served At:** <t:{target['served_at']}:F>",
                    footer_text=f"Warrant Served | #{warrant_id}",
                )
                await inter.response.send_message(f"Warrant **#{warrant_id}** marked as served.", ephemeral=True)
            button.callback = served_callback
            view.add_item(button)

    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


# ---------- /identity DASHBOARD ----------
IDENTITY_COLOR = 0x596744


def identity_roblox_name(member) -> str:
    """Roblox name comes from the server nickname (set by Bloxlink verification)."""
    nick = getattr(member, "nick", None)
    return nick.strip() if nick and nick.strip() else "Not linked"


def identity_license_badge(status: str) -> str:
    if status == "Valid":
        return "<:green_dot:1563693991931940934> **Valid**"
    if status == "Suspended":
        return "<:red_dot:1563694080960237588> **Suspended**"
    return "<:red_dot:1563694080960237588> **Inactive** (license fee unpaid)"


def identity_unpaid(data, user_id):
    unpaid = [c for c in user_citations(data, user_id) if c.get("status") != "Paid"]
    return sorted(unpaid, key=citation_case, reverse=True)


def build_identity_embed(member: discord.Member) -> discord.Embed:
    data = load_citation_data()
    record = refresh_license_status(data, member.id)
    save_citation_data(data)
    citations = user_citations(data, member.id)
    unpaid = [c for c in citations if c.get("status") != "Paid"]
    warrants = active_warrants(data, member.id)

    embed = discord.Embed(
        title="Identity Dashboard",
        description=f"Official civilian record for {member.mention}.",
        color=IDENTITY_COLOR,
    )
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="Roblox Username", value=f"`{identity_roblox_name(member)}`", inline=True)
    embed.add_field(name="Discord Username", value=f"`{member.name}`", inline=True)
    embed.add_field(name="\u200b", value="\u200b", inline=True)

    history = f"**{len(citations)}** total\n**{len(unpaid)}** unpaid"
    embed.add_field(name="Citation History", value=history, inline=True)
    license_text = identity_license_badge(record.get("status", "Valid"))
    if warrants:
        license_text += f"\n{len(warrants)} active warrant{'s' if len(warrants) != 1 else ''}"
    embed.add_field(name="License Status", value=license_text, inline=True)
    embed.add_field(name="\u200b", value="\u200b", inline=True)
    embed.set_footer(text="Identity Dashboard • Only you can see this")
    return embed


class IdentityDashboardView(discord.ui.View):
    def __init__(self, owner_id: int):
        super().__init__(timeout=300)
        self.owner_id = int(owner_id)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("This dashboard belongs to someone else.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="View Citations", style=discord.ButtonStyle.primary)
    async def view_citations(self, interaction: discord.Interaction, button: discord.ui.Button):
        data = load_citation_data()
        citations = sorted(user_citations(data, interaction.user.id), key=citation_case, reverse=True)
        if not citations:
            embed = discord.Embed(
                title="Citation History",
                description="You have no citations on record.",
                color=IDENTITY_COLOR,
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
        view = CitationHistoryView(interaction.user.id, citations)
        await interaction.response.send_message(view=view, ephemeral=True)

    @discord.ui.button(label="Pay Citations", style=discord.ButtonStyle.success)
    async def pay_citations(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed, view = build_pay_panel(interaction.user.id)
        if view is None:
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


class CitationHistoryView(discord.ui.LayoutView):
    """Components V2 card: one section per citation, divided by separators."""
    PER_PAGE = 5

    def __init__(self, owner_id: int, citations: list, page: int = 0):
        super().__init__(timeout=300)
        self.owner_id = int(owner_id)
        self.citations = citations
        self.page = page
        self.pages = max(1, (len(citations) + self.PER_PAGE - 1) // self.PER_PAGE)
        self._build()

    def _citation_text(self, c: dict) -> str:
        paid = c.get("status") == "Paid"
        penalty = f"${int(c.get('fine_amount', 0)):,}"
        if c.get("jail_time"):
            penalty += f" + {c['jail_time']} jail"
        violation = str(c.get("penal_code", "N/A"))
        if len(violation) > 300:
            violation = violation[:297] + "..."
        lines = [
            f"**Citation #{citation_case(c)}**",
            f"**Status:** {'Paid' if paid else 'Unpaid'}",
            f"**Penalty:** {penalty}",
            "**Violation**",
            f"- {violation}",
        ]
        if c.get("issued_at"):
            lines.append(f"-# Issued <t:{int(c['issued_at'])}:d>")
        return "\n".join(lines)

    def _build(self):
        self.clear_items()
        container = discord.ui.Container()
        total = len(self.citations)
        container.add_item(discord.ui.TextDisplay(
            f"## Citation History\n{total} citation{'s' if total != 1 else ''} on record."
        ))
        start = self.page * self.PER_PAGE
        for c in self.citations[start:start + self.PER_PAGE]:
            container.add_item(discord.ui.Separator())
            container.add_item(discord.ui.TextDisplay(self._citation_text(c)))
        container.add_item(discord.ui.Separator())
        container.add_item(discord.ui.TextDisplay(f"-# Page {self.page + 1} of {self.pages}"))

        if self.pages > 1:
            prev_button = discord.ui.Button(
                label="Previous", style=discord.ButtonStyle.secondary, disabled=self.page <= 0
            )
            next_button = discord.ui.Button(
                label="Next", style=discord.ButtonStyle.secondary, disabled=self.page >= self.pages - 1
            )
            prev_button.callback = self._go_prev
            next_button.callback = self._go_next
            row = discord.ui.ActionRow()
            row.add_item(prev_button)
            row.add_item(next_button)
            container.add_item(row)
        self.add_item(container)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("This history belongs to someone else.", ephemeral=True)
            return False
        return True

    async def _go_prev(self, interaction: discord.Interaction):
        self.page = max(0, self.page - 1)
        self._build()
        await interaction.response.edit_message(view=self)

    async def _go_next(self, interaction: discord.Interaction):
        self.page = min(self.pages - 1, self.page + 1)
        self._build()
        await interaction.response.edit_message(view=self)


def build_pay_panel(user_id: int, selected: str = None, notice: str = None):
    """Return (embed, view). view is None when there is nothing left to pay."""
    data = load_citation_data()
    unpaid = identity_unpaid(data, user_id)

    if not unpaid:
        embed = discord.Embed(
            title="Pay Citations" if not notice else "All Caught Up",
            description=(notice + "\n\n" if notice else "") + "You have no unpaid citations.",
            color=IDENTITY_COLOR,
        )
        return embed, None

    if selected not in {str(citation_case(c)) for c in unpaid}:
        selected = None

    wallet = get_user_eco(str(user_id)).get("wallet", 0)
    total_due = sum(int(c.get("fine_amount", 0)) for c in unpaid)
    embed = discord.Embed(
        title="Pay Citations",
        description=(notice + "\n\n" if notice else "") + "Select a citation from the menu, then press **Pay**.",
        color=IDENTITY_COLOR,
    )
    embed.add_field(name="Unpaid Citations", value=f"**{len(unpaid)}**", inline=True)
    embed.add_field(name="Total Due", value=f"**${total_due:,}**", inline=True)
    embed.add_field(name="Wallet", value=f"**${wallet:,}**", inline=True)

    if selected:
        c = data["citations"][selected]
        embed.add_field(
            name=f"Selected: Citation #{selected}",
            value=(
                f"**Violation:** {str(c.get('penal_code', 'N/A'))[:300]}\n"
                f"**Amount:** ${int(c.get('fine_amount', 0)):,}"
            ),
            inline=False,
        )

    record = refresh_license_status(data, user_id)
    save_citation_data(data)
    if active_warrants(data, user_id):
        embed.add_field(name="Action Required", value="Pay your active warrant(s) before paying citations.", inline=False)
    elif not record.get("fee_paid"):
        embed.add_field(name="Action Required", value=f"Pay your ${LICENSE_FEE:,} license fee before paying citations.", inline=False)
    if len(unpaid) > 25:
        embed.set_footer(text=f"Showing the 25 most recent of {len(unpaid)} unpaid citations.")

    return embed, PayCitationsView(user_id, unpaid[:25], selected)


class PayCitationSelect(discord.ui.Select):
    def __init__(self, unpaid: list, selected: str = None):
        options = [
            discord.SelectOption(
                label=f"Citation #{citation_case(c)} — ${int(c.get('fine_amount', 0)):,}",
                description=str(c.get("penal_code", "Citation"))[:100],
                value=str(citation_case(c)),
                default=(str(citation_case(c)) == selected),
            )
            for c in unpaid
        ]
        super().__init__(placeholder="Select a citation to pay...", min_values=1, max_values=1, options=options, row=0)

    async def callback(self, interaction: discord.Interaction):
        embed, view = build_pay_panel(interaction.user.id, selected=self.values[0])
        await interaction.response.edit_message(embed=embed, view=view)


class PayGateView(discord.ui.View):
    """Shown when a warrant or license fee must be handled before citations."""
    def __init__(self, user_id: int, kind: str):
        super().__init__(timeout=300)
        self.user_id = int(user_id)
        label = "View Warrants" if kind == "warrant" else f"Pay License Fee (${LICENSE_FEE:,})"
        button = discord.ui.Button(label=label, style=discord.ButtonStyle.primary)

        async def go(inter: discord.Interaction):
            if kind == "warrant":
                await show_warrants(inter, self.user_id, False)
            else:
                await show_license(inter, self.user_id)

        button.callback = go
        self.add_item(button)


class PayCitationsView(discord.ui.View):
    def __init__(self, owner_id: int, unpaid: list, selected: str = None):
        super().__init__(timeout=300)
        self.owner_id = int(owner_id)
        self.selected = selected
        self.add_item(PayCitationSelect(unpaid, selected))
        self.pay_button.disabled = selected is None

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message("This payment panel belongs to someone else.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Pay", style=discord.ButtonStyle.success, row=1)
    async def pay_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        uid = interaction.user.id
        case_number = self.selected
        if not case_number:
            await interaction.response.send_message("Select a citation first.", ephemeral=True)
            return

        # No awaits between loading and saving, so the same citation can never be paid twice.
        data = load_citation_data()
        record = refresh_license_status(data, uid)
        if active_warrants(data, uid):
            save_citation_data(data)
            await interaction.response.send_message(
                "You must pay your active warrant(s) before you can pay citations.",
                view=PayGateView(uid, "warrant"), ephemeral=True,
            )
            return
        if not record.get("fee_paid"):
            save_citation_data(data)
            await interaction.response.send_message(
                f"You must pay your **${LICENSE_FEE:,} license fee** before you can pay citations.",
                view=PayGateView(uid, "license"), ephemeral=True,
            )
            return

        citation = data.get("citations", {}).get(case_number)
        if not citation or str(citation.get("defendant_id")) != str(uid):
            embed, view = build_pay_panel(uid, notice="That citation could not be found.")
            await interaction.response.edit_message(embed=embed, view=view)
            return
        if citation.get("status") == "Paid":
            embed, view = build_pay_panel(uid, notice=f"Citation **#{case_number}** has already been paid.")
            await interaction.response.edit_message(embed=embed, view=view)
            return

        amount = int(citation.get("fine_amount", 0))
        eco = get_user_eco(str(uid))
        if eco.get("wallet", 0) < amount:
            await interaction.response.send_message(
                f"You need **${amount:,}** in your wallet to pay this citation. "
                f"You currently have **${eco.get('wallet', 0):,}**.",
                ephemeral=True,
            )
            return

        eco["wallet"] -= amount
        eco_data = load_economy()
        eco_data[str(uid)] = eco
        save_economy(eco_data)
        citation["status"] = "Paid"
        citation["paid_at"] = int(central_now().timestamp())
        save_citation_data(data)

        embed, view = build_pay_panel(uid, notice=f"Citation **#{case_number}** paid for **${amount:,}**.")
        await interaction.response.edit_message(embed=embed, view=view)

        await log_citation_event(
            interaction.client, interaction.guild,
            f"Citation Paid | Case #{case_number}",
            f"**Defendant:** <@{uid}>\n**Amount:** ${amount:,}\n**Paid By:** {interaction.user.mention}\n**Penal Code:** {citation.get('penal_code', 'N/A')}",
            footer_text=f"Citation Payment | Case #{case_number}",
        )
        await log_economy(
            interaction.guild, f"Citation Paid | Case #{case_number}",
            f"**User:** <@{uid}>\n**Amount:** ${amount:,}\n**Wallet:** ${eco['wallet']:,}",
            footer=f"Citation Payment | ID: {uid}",
        )


@bot.tree.command(name="identity", description="View your identity dashboard, citations, and license status.")
@app_commands.guild_only()
async def identity_cmd(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("This command can only be used inside a server.", ephemeral=True)
        return
    member = interaction.user
    await interaction.response.send_message(
        embed=build_identity_embed(member),
        view=IdentityDashboardView(member.id),
        ephemeral=True,
    )


@bot.tree.command(name="view-citation", description="View another member's citation, license, and warrant records.")
@app_commands.describe(user="The member whose records you want to view.")
async def view_citation_cmd(interaction: discord.Interaction, user: discord.Member):
    if not (interaction.user.guild_permissions.kick_members or interaction.user.guild_permissions.administrator):
        await interaction.response.send_message("You do not have authorization to view citation records.", ephemeral=True)
        return
    data = load_citation_data()
    record = refresh_license_status(data, user.id)
    citations = user_citations(data, user.id)
    warrants = user_warrants(data, user.id)
    save_citation_data(data)
    await interaction.response.send_message(
        f"**Citation Dashboard — {user.display_name}**\n"
        f"License: **{record['status']}**\n"
        f"Active Warrants: **{len(active_warrants(data, user.id))}**\n"
        f"Total Citations: **{len(citations)}**\n"
        f"Total Warrants: **{len(warrants)}**\n\n"
        "Select an option below:",
        view=CitationDashboardView(user.id, staff_view=True),
        ephemeral=True,
    )


class WarrantCaseModal(discord.ui.Modal, title="Issue Warrant"):
    case_number = discord.ui.TextInput(
        label="Case Number",
        placeholder="e.g. 1001",
        required=True,
        max_length=20,
    )

    async def on_submit(self, interaction: discord.Interaction):
        try:
            case = int(self.case_number.value.strip())
        except ValueError:
            await interaction.response.send_message("Please enter a valid numeric case number.", ephemeral=True)
            return

        data = load_citation_data()
        citation = data.get("citations", {}).get(str(case))
        if not citation:
            await interaction.response.send_message(
                f"Citation case **#{case}** was not found. The officer must issue the normal citation first.",
                ephemeral=True,
            )
            return
        await interaction.response.send_message(
            "Citation found. Review it below and click **Issue Warrant** if a warrant should be requested.",
            embed=discord.Embed(
                title=f"Citation Case #{case}",
                description=citation_display(citation, interaction.guild),
                color=0x596744,
            ),
            view=WarrantIssueView(case),
            ephemeral=True,
        )


class WarrantIssueView(discord.ui.View):
    def __init__(self, case_number):
        super().__init__(timeout=300)
        self.case_number = int(case_number)

    @discord.ui.button(label="Issue Warrant", style=discord.ButtonStyle.success)
    async def issue_button(self, interaction, button):
        if not (interaction.user.guild_permissions.kick_members or interaction.user.guild_permissions.administrator):
            await interaction.response.send_message("You do not have permission to issue a warrant.", ephemeral=True)
            return
        await interaction.response.send_modal(WarrantReasonModal(self.case_number))


class WarrantReasonModal(discord.ui.Modal, title="Warrant Reason"):
    reason = discord.ui.TextInput(
        label="Why?",
        placeholder="Explain why this warrent is being issued. 2+ sentences",
        style=discord.TextStyle.paragraph,
        required=True,
        min_length=20,
        max_length=1500,
    )

    def __init__(self, case_number):
        super().__init__()
        self.case_number = int(case_number)

    async def on_submit(self, interaction: discord.Interaction):
        data = load_citation_data()
        citation = data.get("citations", {}).get(str(self.case_number))
        if not citation:
            await interaction.response.send_message("The citation case no longer exists.", ephemeral=True)
            return

        reason_text = self.reason.value.strip()
        if len([s for s in re.split(r"[.!?]+", reason_text) if s.strip()]) < 2:
            await interaction.response.send_message("The warrant reason must contain at least 2 sentences.", ephemeral=True)
            return

        pending_id = max([int(x) for x in data.get("warrants", {}).keys() if str(x).isdigit()] or [1000]) + 1
        request = {
            "warrant_id": pending_id,
            "case_number": self.case_number,
            "defendant_id": int(citation["defendant_id"]),
            "reason": reason_text,
            "requested_by": interaction.user.id,
            "requested_at": int(central_now().timestamp()),
            "status": "Pending",
        }
        data.setdefault("warrants", {})[str(pending_id)] = request
        save_citation_data(data)

        await log_to_channel(
            bot=interaction.client,
            guild=interaction.guild,
            channel_id=WARRANT_LOG_CHANNEL_ID,
            title=f"Warrant Request | Case #{self.case_number}",
            description=(
                f"**Warrant #:** #{pending_id}\n"
                f"**Citation Case:** #{self.case_number}\n"
                f"**Defendant:** <@{citation['defendant_id']}>\n"
                f"**Requested By:** {interaction.user.mention}\n"
                f"**Reason:** {reason_text}"
            ),
            color=0x596744,
            footer_text=f"Warrant Request #{pending_id}",
        )

        await log_citation_event(
            interaction.client, interaction.guild,
            f"Warrant Requested | Case #{self.case_number}",
            (
                f"**Warrant #:** #{pending_id}\n"
                f"**Citation Case:** #{self.case_number}\n"
                f"**Defendant:** <@{citation['defendant_id']}>\n"
                f"**Requested By:** {interaction.user.mention}\n"
                f"**Reason:** {reason_text}"
            ),
            footer_text=f"Warrant Request #{pending_id}",
        )

        # Find the just-created log message and attach the approval buttons.
        channel = interaction.guild.get_channel(WARRANT_LOG_CHANNEL_ID)
        if channel:
            try:
                messages = [m async for m in channel.history(limit=10)]
                for message in messages:
                    if message.author.id == interaction.client.user.id and message.embeds:
                        if message.embeds[0].title == f"Warrant Request | Case #{self.case_number}":
                            await message.edit(view=WarrantApprovalView(pending_id))
                            break
            except discord.HTTPException:
                pass

        await interaction.response.send_message(
            f"Warrant request **#{pending_id}** submitted to the warrant log for approval.",
            ephemeral=True,
        )


def has_warrant_review_role(member: discord.Member) -> bool:
    """Return True when the member has either configured LEO warrant-review role."""
    if not isinstance(member, discord.Member):
        return False
    return any(role.id in WARRANT_REVIEW_ROLE_IDS for role in member.roles)


class WarrantDenialReasonModal(discord.ui.Modal, title="Deny Warrant"):
    reason = discord.ui.TextInput(
        label="Why is this warrant being denied?",
        style=discord.TextStyle.paragraph,
        placeholder="Explain why this warrant is being denied.",
        required=True,
        min_length=2,
        max_length=1000,
    )

    def __init__(self, warrant_id: int, request_message: discord.Message):
        super().__init__()
        self.warrant_id = int(warrant_id)
        self.request_message = request_message

    async def on_submit(self, interaction: discord.Interaction):
        if not has_warrant_review_role(interaction.user):
            await interaction.response.send_message(
                "You do not have permission to deny warrants.",
                ephemeral=True,
            )
            return

        denial_reason = self.reason.value.strip()
        data = load_citation_data()
        warrant = data.get("warrants", {}).get(str(self.warrant_id))
        if not warrant or warrant.get("status") != "Pending":
            await interaction.response.send_message(
                "This warrant is no longer pending.",
                ephemeral=True,
            )
            return

        warrant["status"] = "Denied"
        warrant["denied_by"] = interaction.user.id
        warrant["denied_at"] = int(central_now().timestamp())
        warrant["denial_reason"] = denial_reason
        save_citation_data(data)

        await log_citation_event(
            interaction.client,
            interaction.guild,
            f"Warrant Denied | #{warrant['warrant_id']}",
            (
                f"**Defendant:** <@{warrant['defendant_id']}>\n"
                f"**Citation Case:** #{warrant['case_number']}\n"
                f"**Warrant Reason:** {warrant['reason']}\n"
                f"**Denial Reason:** {denial_reason}\n"
                f"**Denied By:** {interaction.user.mention}"
            ),
            color=0xCC3333,
            footer_text=f"Warrant Denial | #{warrant['warrant_id']}",
        )

        disabled_view = WarrantApprovalView(self.warrant_id)
        for child in disabled_view.children:
            child.disabled = True

        await self.request_message.edit(
            embed=discord.Embed(
                title=f"Warrant Denied | #{warrant['warrant_id']}",
                description=(
                    f"**Citation Case:** #{warrant['case_number']}\n"
                    f"**Defendant:** <@{warrant['defendant_id']}>\n"
                    f"**Warrant Reason:** {warrant['reason']}\n"
                    f"**Denial Reason:** {denial_reason}\n"
                    f"**Denied By:** {interaction.user.mention}"
                ),
                color=0xCC3333,
            ),
            view=disabled_view,
        )
        await interaction.response.send_message(
            f"Warrant **#{warrant['warrant_id']}** denied. The denial reason was logged.",
            ephemeral=True,
        )


class WarrantApprovalView(discord.ui.View):
    def __init__(self, warrant_id):
        super().__init__(timeout=None)
        self.warrant_id = int(warrant_id)

    @discord.ui.button(label="Approved", style=discord.ButtonStyle.success, custom_id="warrant:approved")
    async def approve(self, interaction, button):
        if not has_warrant_review_role(interaction.user):
            await interaction.response.send_message(
                "You must have one of the authorized LEO roles to approve warrants.",
                ephemeral=True,
            )
            return
        data = load_citation_data()
        warrant = data.get("warrants", {}).get(str(self.warrant_id))
        if not warrant or warrant.get("status") != "Pending":
            await interaction.response.send_message("This warrant is no longer pending.", ephemeral=True)
            return
        citation = data.get("citations", {}).get(str(warrant["case_number"]))
        if not citation:
            await interaction.response.send_message("The linked citation could not be found.", ephemeral=True)
            return
        warrant["status"] = "Active"
        warrant["approved_by"] = interaction.user.id
        warrant["approved_at"] = int(central_now().timestamp())
        citation["warrant_id"] = warrant["warrant_id"]
        refresh_license_status(data, warrant["defendant_id"])
        save_citation_data(data)

        await log_citation_event(
            interaction.client, interaction.guild,
            f"Warrant Approved | #{warrant['warrant_id']}",
            f"**Defendant:** <@{warrant['defendant_id']}>\n**Citation Case:** #{warrant['case_number']}\n**Reason:** {warrant['reason']}\n**Approved By:** {interaction.user.mention}\n**License:** Suspended",
            footer_text=f"Warrant Approval | #{warrant['warrant_id']}",
        )

        defendant = interaction.guild.get_member(int(warrant["defendant_id"]))
        if defendant:
            await send_warrant_dm(interaction.client, defendant, warrant, citation, interaction.guild)

        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(
            embed=discord.Embed(
                title=f"Warrant Approved | #{warrant['warrant_id']}",
                description=(
                    f"**Citation Case:** #{warrant['case_number']}\n"
                    f"**Defendant:** <@{warrant['defendant_id']}>\n"
                    f"**Reason:** {warrant['reason']}\n"
                    f"**Approved By:** {interaction.user.mention}\n"
                    f"**License:** Automatically suspended"
                ),
                color=0x596744,
            ),
            view=self,
        )

    @discord.ui.button(label="Denied", style=discord.ButtonStyle.danger, custom_id="warrant:denied")
    async def deny(self, interaction, button):
        if not has_warrant_review_role(interaction.user):
            await interaction.response.send_message(
                "You must have one of the authorized LEO roles to deny warrants.",
                ephemeral=True,
            )
            return
        data = load_citation_data()
        warrant = data.get("warrants", {}).get(str(self.warrant_id))
        if not warrant or warrant.get("status") != "Pending":
            await interaction.response.send_message("This warrant is no longer pending.", ephemeral=True)
            return

        await interaction.response.send_modal(
            WarrantDenialReasonModal(self.warrant_id, interaction.message)
        )


@bot.tree.command(name="warrent", description="Request a warrant from an existing citation case.")
async def warrent_cmd(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("This command can only be used inside a server.", ephemeral=True)
        return
    if not (interaction.user.guild_permissions.kick_members or interaction.user.guild_permissions.administrator):
        await interaction.response.send_message("You do not have permission to issue warrants.", ephemeral=True)
        return
    await interaction.response.send_modal(WarrantCaseModal())


@tasks.loop(minutes=30)
async def citation_warrant_sweep():
    """Create an automatic warrant once an unpaid citation reaches 7 days."""
    data = load_citation_data()
    now = int(central_now().timestamp())
    changed = False

    for case_number, citation in data.get("citations", {}).items():
        if citation.get("status") == "Paid":
            continue
        if citation.get("warrant_id"):
            continue
        due_at = int(citation.get("due_at", 0) or 0)
        if not due_at or now < due_at:
            continue

        pending_id = max([int(x) for x in data.get("warrants", {}).keys() if str(x).isdigit()] or [1000]) + 1
        warrant = {
            "warrant_id": pending_id,
            "case_number": int(case_number),
            "defendant_id": int(citation["defendant_id"]),
            "reason": "Automatic warrant: citation remained unpaid for 7 days.",
            "requested_by": bot.user.id if bot.user else 0,
            "requested_at": now,
            "approved_by": bot.user.id if bot.user else 0,
            "approved_at": now,
            "status": "Active",
            "automatic": True,
            "served": False,
        }
        data.setdefault("warrants", {})[str(pending_id)] = warrant
        citation["warrant_id"] = pending_id
        changed = True

        refresh_license_status(data, warrant["defendant_id"])
        for guild in bot.guilds:
            defendant = guild.get_member(warrant["defendant_id"])
            if defendant:
                try:
                    await send_warrant_dm(bot, defendant, warrant, citation, guild)
                except Exception as exc:
                    print(f"Automatic warrant DM failed: {exc!r}")

            try:
                await log_citation_event(
                    bot, guild,
                    f"Automatic Warrant | Case #{case_number}",
                    (
                        f"**Warrant #:** #{pending_id}\n"
                        f"**Citation Case:** #{case_number}\n"
                        f"**Defendant:** <@{warrant['defendant_id']}>\n"
                        f"**Reason:** {warrant['reason']}\n"
                        f"**Created:** <t:{now}:F>"
                    ),
                    footer_text="Automatic 7-Day Citation Warrant",
                )
                await log_to_channel(
                    bot=bot,
                    guild=guild,
                    channel_id=WARRANT_LOG_CHANNEL_ID,
                    title=f"Automatic Warrant | Case #{case_number}",
                    description=(
                        f"**Warrant #:** #{pending_id}\n"
                        f"**Citation Case:** #{case_number}\n"
                        f"**Defendant:** <@{warrant['defendant_id']}>\n"
                        f"**Reason:** {warrant['reason']}\n"
                        f"**Created:** <t:{now}:F>"
                    ),
                    color=0x596744,
                    footer_text="Automatic 7-Day Citation Warrant",
                )
                break
            except Exception as exc:
                print(f"Automatic warrant log failed in guild {guild.id}: {exc!r}")

    if changed:
        save_citation_data(data)


@citation_warrant_sweep.before_loop
async def before_citation_warrant_sweep():
    await bot.wait_until_ready()


# --- MODERATION LOGIC ---

async def log_action(ctx, target_user: discord.User, action_label: str, reason_input: str):
    data = load_data()
    case_id = data["next_case"]
    data["next_case"] += 1
    user_id = str(target_user.id)
    if user_id not in data["users"]:
        data["users"][user_id] = []

    unix_time = int(central_now().timestamp())

    evidence = ""
    reason = reason_input
    
    if "|" in reason_input:
        parts = reason_input.split("|", 1)
        reason = parts[0].strip()
        evidence = parts[1].strip()

    entry = {
        "case_id": case_id,
        "type": action_label,
        "moderator": ctx.author.name,
        "reason": reason,
        "evidence": evidence,
        "timestamp": unix_time,
    }
    data["users"][user_id].append(entry)
    save_data(data)

    member = ctx.guild.get_member(target_user.id)
    role_name = PUNISHMENT_ROLES.get(action_label)
    if member and role_name:
        role = discord.utils.get(ctx.guild.roles, name=role_name)
        if role:
            try:
                await member.add_roles(role)
            except discord.Forbidden:
                pass

    dm_sections = [
        f"**Case ID:** #{case_id}",
        f"**Offense Reason:** {reason}"
    ]
    if evidence:
        dm_sections.append(f"**Provided Evidence:** {evidence}")

    sent = await send_v2_dm(
        bot=ctx.bot,
        user=target_user,
        title=f"Moderation Action: {action_label}",
        body_text=f"You have received a moderation action in **{ctx.guild.name}**.\n<t:{unix_time}:F>",
        inner_sections=dm_sections
    )

    if not sent:
        await ctx.send("User could not be DM'd (DMs locked or bot blocked).")

    log_description = (
        f"**Target:** <@{target_user.id}>\n"
        f"**Action:** {action_label}\n"
        f"**Reason:** {reason}\n"
    )
    if evidence:
        log_description += f"**Evidence:** {evidence}\n"
    
    log_description += f"**Issued:** <t:{unix_time}:F>"

    embed = discord.Embed(
        title=f"Case #{case_id} | {action_label}",
        description=log_description,
        color=0xCC3333,
    )
    embed.set_footer(text=f"Moderator: @{ctx.author.name}")
    
    await ctx.send(content=f"<@{target_user.id}>", embed=embed)

    await log_to_channel(
        bot=ctx.bot,
        guild=ctx.guild,
        channel_id=MOD_LOG_CHANNEL_ID,
        title=f"Case #{case_id} | {action_label}",
        description=log_description,
        color=0xCC3333,
        footer_text=f"Moderator: @{ctx.author.name} | ID: {target_user.id}"
    )


# --- GENERAL MODERATION PREFIX COMMANDS ---

@bot.command()
@commands.has_role(AUTHORIZED_PREFIX_ROLE)
async def warn1(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Warn 1", reason)

@bot.command()
@commands.has_role(AUTHORIZED_PREFIX_ROLE)
async def warn2(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Warn 2", reason)

@bot.command()
@commands.has_role(AUTHORIZED_PREFIX_ROLE)
async def strike1(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Strike 1", reason)

@bot.command()
@commands.has_role(AUTHORIZED_PREFIX_ROLE)
async def strike2(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Strike 2", reason)

@bot.command(aliases=["infraction1"])
@commands.has_role(AUTHORIZED_PREFIX_ROLE)
async def infract1(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Infract 1", reason)

@bot.command(aliases=["infraction2"])
@commands.has_role(AUTHORIZED_PREFIX_ROLE)
async def infract2(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Infract 2", reason)


# Civilian restriction actions are handled by the /civres slash command below.


# --- TEMPORARY CIVILIAN RESTRICTIONS (/civres) ---
CIVRES_ROLE_IDS = {1: 1542733409254645801, 2: 1542733440447807488}
CIVRES_DATA_FILE = "civres_active.json"


def load_civres_data():
    return load_json(CIVRES_DATA_FILE, {"active": {}})


def save_civres_data(data):
    save_json(CIVRES_DATA_FILE, data)


def parse_civres_duration(raw: str) -> int:
    """Parse a duration such as 30m, 2h, 1d 12h, or 1w."""
    text = (raw or "").strip().lower()
    pattern = re.compile(r"(\d+)\s*(weeks?|wks?|w|days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)(?![a-z])")
    matches = list(pattern.finditer(text))
    if not matches:
        raise ValueError("Use a duration such as 30m, 2h, 1d, or 1d 12h.")
    residue = pattern.sub("", text)
    residue = re.sub(r"[\s,]+|\band\b", "", residue)
    if residue:
        raise ValueError("Use a duration such as 30m, 2h, 1d, or 1d 12h.")
    seconds = 0
    for match in matches:
        n = int(match.group(1))
        unit = match.group(2)[0]
        seconds += n * {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
    if seconds < 1 or seconds > 31536000:
        raise ValueError("Duration must be between 1 second and 365 days.")
    return seconds


async def civres_log(guild: discord.Guild, *, title: str, description: str, color: int = 0xCC3333):
    await log_to_channel(
        bot=bot, guild=guild, channel_id=MOD_LOG_CHANNEL_ID,
        title=title, description=description, color=color,
        footer_text="Civilian Restriction System"
    )


def civres_add_case_update(user_id: int, case_id: int, event: str, details: str, timestamp: int | None = None):
    """Attach lifecycle events to the same record shown by -modlogs/-caselogs."""
    data = load_data()
    users = data.setdefault("users", {})
    records = users.setdefault(str(user_id), [])
    for record in records:
        if str(record.get("case_id")) == str(case_id):
            updates = record.setdefault("updates", [])
            updates.append({
                "event": event,
                "details": details,
                "timestamp": timestamp or int(datetime.now(timezone.utc).timestamp()),
            })
            save_data(data)
            return True
    return False



class CivResAppealModal(discord.ui.Modal, title="Civilian Restriction Appeal"):
    user_id_field = discord.ui.TextInput(label="User ID", placeholder="Your Discord user ID", max_length=25, required=True)
    restriction_reason_field = discord.ui.TextInput(label="Reason you were Civilian Restricted", style=discord.TextStyle.paragraph, max_length=1000, required=True)
    appeal_reason_field = discord.ui.TextInput(label="Why should we accept your appeal?", style=discord.TextStyle.paragraph, max_length=1000, required=True)

    def __init__(self, expected_user_id: int, case_id: int):
        super().__init__()
        self.expected_user_id = expected_user_id
        self.case_id = case_id

    async def on_submit(self, interaction: discord.Interaction):
        if interaction.user.id != self.expected_user_id:
            await interaction.response.send_message("This appeal form belongs to a different user.", ephemeral=True)
            return
        provided_id = str(self.user_id_field.value).strip()
        if provided_id != str(interaction.user.id):
            await interaction.response.send_message("The User ID must match your Discord account ID. Please submit the form again with the correct ID.", ephemeral=True)
            return
        # Acknowledge the modal submission immediately so Discord does not time out
        # while the appeal is being logged and posted to the review channel.
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            channel = bot.get_channel(CIVRES_APPEAL_CHANNEL_ID) or await bot.fetch_channel(CIVRES_APPEAL_CHANNEL_ID)
            guild = channel.guild
            embed = discord.Embed(title=f"Civilian Restriction Appeal | Case #{self.case_id}", color=0xD9A441)
            embed.add_field(name="User", value=f"<@{interaction.user.id}> (`{interaction.user.id}`)", inline=False)
            embed.add_field(name="Restriction Case", value=f"#{self.case_id}", inline=True)
            embed.add_field(name="User ID Provided", value=f"`{provided_id}`", inline=True)
            embed.add_field(name="Reason for Civilian Restriction", value=str(self.restriction_reason_field.value), inline=False)
            embed.add_field(name="Why the Appeal Should Be Accepted", value=str(self.appeal_reason_field.value), inline=False)
            embed.add_field(name="Status", value="Pending review", inline=False)
            view = CivResAppealReviewView(interaction.user.id, self.case_id)
            await channel.send(embed=embed, view=view, allowed_mentions=discord.AllowedMentions.none())
            now = int(datetime.now(timezone.utc).timestamp())
            civres_add_case_update(interaction.user.id, self.case_id, "Appeal Submitted", "Appeal submitted and sent for staff review.", now)
            await civres_log(guild, title=f"CivRes Appeal Submitted | Case #{self.case_id}", description=(
                f"**User:** <@{interaction.user.id}> (`{interaction.user.id}`)\n"
                f"**Appeal channel:** <#{CIVRES_APPEAL_CHANNEL_ID}>\n"
                f"**Status:** Pending review\n**Submitted:** <t:{now}:F>"
            ), color=0xD9A441)
        except Exception as exc:
            print(f"[civres appeal] Could not post appeal for {interaction.user.id}: {exc!r}")
            await interaction.followup.send("Your appeal could not be delivered. Please contact server management.", ephemeral=True)
            return
        await interaction.followup.send("Your civilian restriction appeal has been submitted for review.", ephemeral=True)


class CivResDenyModal(discord.ui.Modal, title="Deny Civilian Restriction Appeal"):
    denial_reason = discord.ui.TextInput(label="Reason for denial", style=discord.TextStyle.paragraph, placeholder="Explain why the appeal was denied. This will be sent to the user.", max_length=1000, required=True)

    def __init__(self, user_id: int, case_id: int, review_message_id: int):
        super().__init__()
        self.user_id = user_id
        self.case_id = case_id
        self.review_message_id = review_message_id

    async def on_submit(self, interaction: discord.Interaction):
        if not interaction.guild or not isinstance(interaction.user, discord.Member) or not has_role_or_above(interaction.user, SERVER_STAFF_ROLE_ID):
            await interaction.response.send_message("You need Server Staff or a higher role to review appeals.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        reason = str(self.denial_reason.value).strip()
        event_time = int(datetime.now(timezone.utc).timestamp())
        civres_add_case_update(self.user_id, self.case_id, "Appeal Denied", f"Denied by {interaction.user} ({interaction.user.id}). Reason: {reason}", event_time)
        try:
            log_guild = interaction.guild
            await civres_log(log_guild, title=f"CivRes Appeal Denied | Case #{self.case_id}", description=(
                f"**User:** <@{self.user_id}> (`{self.user_id}`)\n**Decision by:** <@{interaction.user.id}>\n"
                f"**Reason:** {reason}\n**Decision time:** <t:{event_time}:F>"
            ), color=0xCC3333)
        except Exception as exc:
            print(f"[civres appeal] Could not post denial to moderation logs: {exc!r}")
        try:
            user = bot.get_user(self.user_id) or await bot.fetch_user(self.user_id)
            await send_v2_dm(bot, user, "Civilian Restriction Appeal Denied", f"Your appeal for Civ Restriction case **#{self.case_id}** was denied.", [f"**Decision by:** {interaction.user}", f"**Reason:** {reason}"])
        except Exception as exc:
            print(f"[civres appeal] Could not DM denial to {self.user_id}: {exc!r}")
        try:
            msg = interaction.message
            if msg and msg.embeds:
                embed = msg.embeds[0]
                embed.color = 0xCC3333
                # Replace pending status field, preserving all other fields.
                fields = list(embed.fields)
                embed.clear_fields()
                for field in fields:
                    if field.name == "Status":
                        embed.add_field(name="Status", value=f"Denied by {interaction.user.mention}\n**Reason:** {reason}", inline=False)
                    else:
                        embed.add_field(name=field.name, value=field.value, inline=field.inline)
                await msg.edit(embed=embed, view=None, allowed_mentions=discord.AllowedMentions.none())
        except Exception as exc:
            print(f"[civres appeal] Could not update denial log: {exc!r}")
        await interaction.followup.send("Appeal denied and the user has been notified where DMs are open.", ephemeral=True)


class CivResAppealReviewView(discord.ui.View):
    def __init__(self, user_id: int, case_id: int):
        super().__init__(timeout=None)
        self.user_id = user_id
        self.case_id = case_id

    @discord.ui.button(label="Accept", style=discord.ButtonStyle.success, custom_id="civres_appeal_accept")
    async def accept_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.guild or not isinstance(interaction.user, discord.Member) or not has_role_or_above(interaction.user, SERVER_STAFF_ROLE_ID):
            await interaction.response.send_message("You need Server Staff or a higher role to review appeals.", ephemeral=True)
            return
        if interaction.message and interaction.message.embeds and any(f.name == "Status" and f.value != "Pending review" for f in interaction.message.embeds[0].fields):
            await interaction.response.send_message("This appeal has already been reviewed.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        # An accepted appeal ends the active restriction immediately and restores the saved roles.
        try:
            guild = interaction.guild
            active_data = load_civres_data()
            active_records = active_data.setdefault("active", {})
            active_key = f"{guild.id}:{self.user_id}"
            active_record = active_records.get(active_key)
            member = guild.get_member(self.user_id)
            if member is None:
                try:
                    member = await guild.fetch_member(self.user_id)
                except discord.HTTPException:
                    member = None
            if active_record and member:
                role_id = int(active_record.get("restriction_role_id", 0))
                current_restriction = guild.get_role(role_id)
                if current_restriction and current_restriction in member.roles:
                    await member.remove_roles(current_restriction, reason=f"CivRes appeal case #{self.case_id} accepted by {interaction.user}")
                restored = []
                for role_id in active_record.get("removed_role_ids", active_record.get("old_role_ids", [])):
                    role = guild.get_role(int(role_id))
                    if role and not role.managed and role not in member.roles and role < guild.me.top_role:
                        restored.append(role)
                if restored:
                    await member.add_roles(*restored, reason=f"CivRes appeal case #{self.case_id} accepted by {interaction.user}")
                active_records.pop(active_key, None)
                save_civres_data(active_data)
                event_time = int(datetime.now(timezone.utc).timestamp())
                civres_add_case_update(self.user_id, self.case_id, "Appeal Accepted", f"Accepted by {interaction.user} ({interaction.user.id}); restriction removed and {len(restored)} role(s) restored.", event_time)
                await civres_log(guild, title=f"CivRes Appeal Accepted | Case #{self.case_id}", description=f"**User:** <@{self.user_id}> (`{self.user_id}`)\n**Decision by:** <@{interaction.user.id}>\n**Roles restored:** {len(restored)}\n**Restriction removed:** Yes\n**Decision time:** <t:{event_time}:F>", color=0x33AA55)
            user = bot.get_user(self.user_id) or await bot.fetch_user(self.user_id)
            await send_v2_dm(bot, user, "Civilian Restriction Appeal Accepted", f"Your appeal for Civ Restriction case **#{self.case_id}** has been accepted.", [f"**Decision by:** {interaction.user}", "Your active civilian restriction has been removed and your previously removed roles have been restored where Discord permissions allow."])
        except Exception as exc:
            print(f"[civres appeal] Could not fully process accepted appeal for {self.user_id}: {exc!r}")
            await interaction.followup.send("The appeal was accepted, but role restoration encountered an error. Check the bot logs.", ephemeral=True)
            return
        if interaction.message and interaction.message.embeds:
            embed = interaction.message.embeds[0]
            embed.color = 0x33AA55
            for i, field in enumerate(embed.fields):
                if field.name == "Status":
                    embed.set_field_at(i, name="Status", value=f"Accepted by {interaction.user.mention}", inline=False)
                    break
            await interaction.message.edit(embed=embed, view=None, allowed_mentions=discord.AllowedMentions.none())
        await interaction.followup.send("Appeal accepted and the user has been notified where DMs are open.", ephemeral=True)

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.danger, custom_id="civres_appeal_deny")
    async def deny_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.guild or not isinstance(interaction.user, discord.Member) or not has_role_or_above(interaction.user, SERVER_STAFF_ROLE_ID):
            await interaction.response.send_message("You need Server Staff or a higher role to review appeals.", ephemeral=True)
            return
        await interaction.response.send_modal(CivResDenyModal(self.user_id, self.case_id, interaction.message.id if interaction.message else 0))


@bot.tree.command(name="civres", description="Apply a timed civilian restriction and restore the user's previous roles afterward.")
@app_commands.describe(
    user="Member receiving the restriction",
    level="Civilian Restriction 1 or 2",
    reason="Reason for the restriction",
    evidence="Evidence link or details",
    duration="How long it lasts (e.g. 30m, 2h, 1d 12h)"
)
@app_commands.choices(level=[
    app_commands.Choice(name="Civ Restriction 1", value=1),
    app_commands.Choice(name="Civ Restriction 2", value=2),
])
async def civres_slash(
    interaction: discord.Interaction,
    user: discord.Member,
    level: app_commands.Choice[int],
    reason: str,
    evidence: str,
    duration: str,
):
    if not interaction.guild or not isinstance(interaction.user, discord.Member) or not has_role_or_above(interaction.user, SERVER_STAFF_ROLE_ID):
        await interaction.response.send_message("You need Server Staff or a higher role to use this command.", ephemeral=True)
        return
    try:
        seconds = parse_civres_duration(duration)
    except ValueError as exc:
        await interaction.response.send_message(str(exc), ephemeral=True)
        return

    guild = interaction.guild
    target = guild.get_member(user.id)
    if target is None:
        await interaction.response.send_message("That member is no longer in this server.", ephemeral=True)
        return
    restriction_role = guild.get_role(CIVRES_ROLE_IDS[level.value])
    if restriction_role is None:
        await interaction.response.send_message(f"Couldn't find the configured Civ Restriction {level.value} role.", ephemeral=True)
        return
    if target.id == interaction.user.id or target.id == guild.owner_id or target.bot:
        await interaction.response.send_message("You cannot apply this restriction to yourself, the server owner, or a bot.", ephemeral=True)
        return
    if target.top_role >= guild.me.top_role:
        await interaction.response.send_message("I can't manage this member because their highest role is at or above my highest role.", ephemeral=True)
        return

    data = load_civres_data()
    active = data.setdefault("active", {})
    key = f"{guild.id}:{target.id}"
    if key in active:
        await interaction.response.send_message("This member already has an active timed civilian restriction. Let it expire before applying another.", ephemeral=True)
        return

    await interaction.response.defer(ephemeral=True, thinking=True)
    old_roles = [r for r in target.roles if r != guild.default_role and not r.managed and r.id not in CIVRES_ROLE_IDS.values()]
    role_ids = [r.id for r in old_roles]
    removed_roles = []
    failed_roles = []
    for role in old_roles:
        try:
            await target.remove_roles(role, reason=f"Timed Civ Restriction {level.value} issued by {interaction.user} | {reason}")
            removed_roles.append(role.id)
        except (discord.Forbidden, discord.HTTPException):
            failed_roles.append(role.id)

    # Remove any previous Civ Restriction role, then apply the selected one.
    for rid in CIVRES_ROLE_IDS.values():
        existing = guild.get_role(rid)
        if existing and existing in target.roles and existing.id != restriction_role.id:
            try:
                await target.remove_roles(existing, reason="Replacing civilian restriction role")
            except (discord.Forbidden, discord.HTTPException):
                pass
    try:
        await target.add_roles(restriction_role, reason=f"Timed Civ Restriction {level.value} issued by {interaction.user} | {reason}")
    except (discord.Forbidden, discord.HTTPException) as exc:
        # Best effort restore if the restriction role could not be applied.
        restore = [guild.get_role(rid) for rid in removed_roles]
        restore = [r for r in restore if r is not None]
        if restore:
            try:
                await target.add_roles(*restore, reason="Rollback: failed to apply civilian restriction")
            except (discord.Forbidden, discord.HTTPException):
                pass
        await interaction.followup.send(f"I couldn't apply the restriction role: {exc.__class__.__name__}. Check my role hierarchy and Manage Roles permission.", ephemeral=True)
        return

    now = int(datetime.now(timezone.utc).timestamp())
    expires_at = now + seconds
    active[key] = {
        "guild_id": guild.id,
        "user_id": target.id,
        "restriction_level": level.value,
        "restriction_role_id": restriction_role.id,
        "old_role_ids": role_ids,
        "removed_role_ids": removed_roles,
        "issued_by": interaction.user.id,
        "issued_by_name": str(interaction.user),
        "case_id": None,
        "reason": reason,
        "evidence": evidence,
        "issued_at": now,
        "expires_at": expires_at,
    }
    save_civres_data(data)

    # Allocate a case number in the existing moderation case database.
    mod_data = load_data()
    case_id = mod_data.get("next_case", 1000)
    mod_data["next_case"] = case_id + 1
    mod_data.setdefault("users", {}).setdefault(str(target.id), []).append({
        "case_id": case_id, "type": f"Civ Restriction {level.value}",
        "moderator": str(interaction.user), "reason": reason, "evidence": evidence,
        "timestamp": now, "duration": duration, "expires_at": expires_at,
    })
    save_data(mod_data)
    active[key]["case_id"] = case_id
    save_civres_data(data)

    description = (
        f"**Target:** <@{target.id}> (`{target.id}`)\n"
        f"**Action:** Civ Restriction {level.value}\n"
        f"**Reason:** {reason}\n**Evidence:** {evidence}\n"
        f"**Duration:** {duration}\n**Expires:** <t:{expires_at}:F> (<t:{expires_at}:R>)\n"
        f"**Roles removed:** {len(removed_roles)}\n**Roles not removable:** {len(failed_roles)}\n"
        f"**Moderator:** <@{interaction.user.id}>\n**Case:** #{case_id}"
    )
    await civres_log(guild, title=f"Case #{case_id} | Civ Restriction {level.value} Issued", description=description)
    dm_sent = False
    try:
        dm_channel = target.dm_channel or await target.create_dm()
        v2_components = build_v2_payload(
            f"Civ Restriction {level.value}",
            f"A civilian restriction has been issued to you in **{guild.name}**.\n**Duration:** {duration}\n**Expires:** <t:{expires_at}:F> (<t:{expires_at}:R>)",
            [f"**Case:** #{case_id}", f"**Reason:** {reason}", f"**Evidence:** {evidence}", "Your previous roles will be restored automatically when the restriction expires, where Discord permissions allow."]
        )
        v2_components[0]["components"].append({"type": 1, "components": [{"type": 2, "style": 1, "label": "Appeal", "custom_id": f"civres_appeal_open:{target.id}:{case_id}"}]})
        await bot.http.request(discord.http.Route('POST', '/channels/{channel_id}/messages', channel_id=dm_channel.id), json={"components": v2_components, "flags": 32768})
        dm_sent = True
    except Exception as exc:
        print(f"Could not DM Civ Restriction notice to user {target.id}: {exc!r}")
    if not dm_sent:
        print(f"Could not DM Civ Restriction notice to user {target.id}.")
    extra = f" {len(failed_roles)} role(s) could not be removed due to Discord role restrictions." if failed_roles else ""
    await interaction.followup.send(f"Applied Civ Restriction {level.value} to {target.mention}. Expires <t:{expires_at}:R>. Case #{case_id}.{extra}", ephemeral=True)



@bot.listen("on_interaction")
async def civres_appeal_component_router(interaction: discord.Interaction):
    if interaction.type != discord.InteractionType.component or not interaction.data:
        return
    custom_id = interaction.data.get("custom_id", "")
    if not custom_id.startswith("civres_appeal_open:"):
        return
    try:
        _, user_id, case_id = custom_id.split(":", 2)
        expected_user_id, case_number = int(user_id), int(case_id)
    except (ValueError, TypeError):
        await interaction.response.send_message("This appeal button is invalid.", ephemeral=True)
        return
    if interaction.user.id != expected_user_id:
        await interaction.response.send_message("This appeal button belongs to a different user.", ephemeral=True)
        return
    await interaction.response.send_modal(CivResAppealModal(expected_user_id, case_number))


@tasks.loop(seconds=30)
async def civres_expiry_sweep():
    data = load_civres_data()
    active = data.setdefault("active", {})
    now = int(datetime.now(timezone.utc).timestamp())
    changed = False
    for key, record in list(active.items()):
        if int(record.get("expires_at", 0)) > now:
            continue
        guild = bot.get_guild(int(record.get("guild_id", 0)))
        if guild is None:
            continue
        member = guild.get_member(int(record.get("user_id", 0)))
        if member is None:
            # Keep the record so restoration can be attempted if they rejoin.
            continue
        restored_ids = []
        failed_ids = []
        current_restriction = guild.get_role(int(record.get("restriction_role_id", 0)))
        if current_restriction and current_restriction in member.roles:
            try:
                await member.remove_roles(current_restriction, reason="Timed civilian restriction expired")
            except (discord.Forbidden, discord.HTTPException):
                failed_ids.append(current_restriction.id)
        for rid in record.get("removed_role_ids", record.get("old_role_ids", [])):
            role = guild.get_role(int(rid))
            if role is None or role.managed or role in member.roles:
                continue
            try:
                await member.add_roles(role, reason="Restore roles after timed civilian restriction")
                restored_ids.append(role.id)
            except (discord.Forbidden, discord.HTTPException):
                failed_ids.append(role.id)
        desc = (
            f"**Target:** <@{member.id}> (`{member.id}`)\n"
            f"**Action:** Civ Restriction {record.get('restriction_level', '?')} expired\n"
            f"**Original reason:** {record.get('reason', 'Not recorded')}\n"
            f"**Roles restored:** {len(restored_ids)}\n**Roles needing manual restoration:** {len(failed_ids)}\n"
            f"**Issued by:** <@{record.get('issued_by', 0)}>\n**Expired:** <t:{now}:F>"
        )
        await civres_log(guild, title=f"Civ Restriction Expired | {member}", description=desc, color=0x33AA55)
        case_id = record.get("case_id")
        if case_id is not None:
            civres_add_case_update(member.id, int(case_id), "Restriction Expired", f"Automatic expiry processed. {len(restored_ids)} role(s) restored; {len(failed_ids)} role operation(s) need manual review.", now)
        del active[key]
        changed = True
    if changed:
        save_civres_data(data)


@civres_expiry_sweep.before_loop
async def before_civres_expiry_sweep():
    await bot.wait_until_ready()


# --- STAFF INFRACTIONS & BLACKLIST COMMANDS ---

@bot.command()
@commands.has_any_role(*STAFF_INFRACT_ROLES)
async def staffinfract1(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Staff Infraction 1", reason)

@bot.command()
@commands.has_any_role(*STAFF_INFRACT_ROLES)
async def staffinfract2(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Staff Infraction 2", reason)

@bot.command()
@commands.has_any_role(*STAFF_INFRACT_ROLES)
async def staffinfract3(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Staff Infraction 3", reason)

@bot.command()
@commands.has_any_role(*STAFF_BLACKLIST_ROLES)
async def staffblacklist(ctx, target: discord.User, *, reason: str = "No reason given."):
    await log_action(ctx, target, "Staff Blacklist", reason)


# --- ROLE HIERARCHY HELPERS ---

def has_role_or_above(member: discord.Member, role_id: int) -> bool:
    """Return True when the member has the specified role or a higher role."""
    if not isinstance(member, discord.Member):
        return False
    if member.guild.owner_id == member.id or member.guild_permissions.administrator:
        return True

    required_role = member.guild.get_role(role_id)
    if required_role is None:
        return False

    return member.top_role.position >= required_role.position


def role_or_above_check(role_id: int):
    async def predicate(ctx):
        return has_role_or_above(ctx.author, role_id)
    return commands.check(predicate)


# --- CASELOGS PREFIX COMMAND ---

def caselogs_access():
    async def predicate(ctx):
        # Server owner can always use case log commands.
        if ctx.guild and ctx.author.id == ctx.guild.owner_id:
            return True

        # Otherwise require the configured authorized role.
        return any(role.id == AUTHORIZED_PREFIX_ROLE for role in getattr(ctx.author, "roles", []))

    return commands.check(predicate)


@bot.command(aliases=["caselog", "modlogs", "moglogs", "moderations", "logs", "history"])
@caselogs_access()
async def caselogs(ctx, target: discord.User = None):
    """Show moderation/case logs for a user.

    Prefix commands use - only.
    Examples: -caselogs, -caselogs @User, -modlogs @User, -moglogs @User
    """
    target_user = target or ctx.author
    data = load_data()
    if not isinstance(data, dict):
        data = {"next_case": 1000, "users": {}}
    if not isinstance(data.get("users"), dict):
        data["users"] = {}

    user_id = str(target_user.id)
    user_logs = data["users"].get(user_id, [])
    if not isinstance(user_logs, list):
        user_logs = []

    if not user_logs:
        embed = discord.Embed(
            description=f"No moderation logs found for <@{target_user.id}> (`{target_user.id}`).",
            color=0x596744,
        )
        await ctx.send(embed=embed)
        return

    embed = discord.Embed(
        title=f"Modlogs for {target_user.name}",
        description=f"<@{target_user.id}>\n\n" + "—" * 15,
        color=0x596744,
    )
    for case in reversed(user_logs):
        log_block = f"**Mod:** @{case['moderator']}\n**Reason:** {case['reason']}\n"
        if case.get("evidence"):
            log_block += f"**Evidence:** {case['evidence']}\n"
            
        ts_val = case.get('timestamp')
        time_str = f"<t:{ts_val}:F>" if isinstance(ts_val, int) else ts_val
        log_block += f"**Issued:** {time_str}"
        for update in case.get("updates", []):
            update_ts = update.get("timestamp")
            update_time = f"<t:{update_ts}:F>" if isinstance(update_ts, int) else "Time not recorded"
            log_block += f"\n\n**{update.get('event', 'Update')}:** {update.get('details', '')}\n**Updated:** {update_time}"

        embed.add_field(
            name=f"Case #{case['case_id']} — {case['type']}",
            value=log_block,
            inline=False,
        )
    await ctx.send(embed=embed)


@bot.command()
@role_or_above_check(SERVER_STAFF_ROLE_ID)
async def purge(ctx, amount: int):
    """Delete exactly `amount` non-pinned messages sent before the command, then remove the command itself.

    The `-purge` message is never counted toward `amount`. Pinned messages are never deleted.
    """
    if amount <= 0:
        await ctx.send("The purge amount must be greater than 0.", delete_after=8)
        return

    # Collect exactly the requested number of deletable messages that were sent BEFORE the
    # command message, so the command is not part of the count. Pinned messages are skipped.
    messages_to_delete = []
    try:
        async for msg in ctx.channel.history(limit=None, before=ctx.message):
            if msg.pinned:
                continue
            messages_to_delete.append(msg)
            if len(messages_to_delete) >= amount:
                break
    except discord.HTTPException as exc:
        print(f"Purge history lookup failed: {exc!r}")
        await delete_command_message(ctx)
        await ctx.send("I could not read the channel history to perform the purge.", delete_after=8)
        return

    if not messages_to_delete:
        await delete_command_message(ctx)
        await ctx.send("There are no non-pinned messages available to purge.", delete_after=8)
        return

    deleted_count = 0
    now = central_now()
    fourteen_days = timedelta(days=14)

    # Bulk delete messages that are young enough, then individually delete
    # older messages. This still deletes exactly the selected non-pinned messages.
    recent = [m for m in messages_to_delete if (now - m.created_at) < fourteen_days]
    old = [m for m in messages_to_delete if (now - m.created_at) >= fourteen_days]

    for start in range(0, len(recent), 100):
        chunk = recent[start:start + 100]
        if not chunk:
            continue
        try:
            await ctx.channel.delete_messages(chunk, reason=f"Purge by {ctx.author} ({amount})")
            deleted_count += len(chunk)
        except discord.HTTPException:
            # Fall back to individual deletion if Discord rejects the bulk request.
            for msg in chunk:
                try:
                    await msg.delete(reason=f"Purge by {ctx.author}")
                    deleted_count += 1
                except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                    pass

    for msg in old:
        try:
            await msg.delete(reason=f"Purge by {ctx.author}")
            deleted_count += 1
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass

    # Remove the -purge command message separately. It is not part of deleted_count.
    await delete_command_message(ctx)

    # Prefix-command responses cannot be truly ephemeral in Discord.
    # Auto-delete the confirmation so it does not remain visible in the channel.
    summary = f"Deleted {deleted_count} message{'s' if deleted_count != 1 else ''}"
    if deleted_count != amount:
        summary += f" (of {amount} requested)"
    await ctx.send(summary + ".", delete_after=2)



# --- /modreq SLASH COMMAND ---

@bot.tree.command(name="modreq", description="Submit a moderation request for review.")
@app_commands.describe(
    type="The type of moderation action being requested",
    user="The member this request concerns",
    reason="The reason for this moderation request",
    evidence="Evidence supporting this moderation request",
)
@app_commands.choices(
    type=[
        app_commands.Choice(name="Warn", value="Warn"),
        app_commands.Choice(name="Strike", value="Strike"),
        app_commands.Choice(name="Infraction", value="Infraction"),
        app_commands.Choice(name="Kick", value="Kick"),
        app_commands.Choice(name="Ban", value="Ban"),
    ]
)
async def modreq_cmd(
    interaction: discord.Interaction,
    type: app_commands.Choice[str],
    user: discord.Member,
    reason: str,
    evidence: str,
):
    is_ban = type.value == "Ban"
    target_channel_id = MODREQ_BAN_CHANNEL_ID if is_ban else MODREQ_STANDARD_CHANNEL_ID
    ping_role_id = MODREQ_BAN_PING_ROLE if is_ban else MODREQ_STANDARD_PING_ROLE

    target_channel = interaction.guild.get_channel(target_channel_id)
    if target_channel is None:
        try:
            target_channel = await interaction.guild.fetch_channel(target_channel_id)
        except Exception:
            await interaction.response.send_message(
                "The moderation request channel could not be found. Please contact an administrator.",
                ephemeral=True,
            )
            return

    unix_time = int(central_now().timestamp())

    sections = [
        f"**Requested Action**\n{type.value}",
        f"**Target User**\n{user.mention} (`{user.id}`)",
        f"**Reason**\n{reason}",
        f"**Evidence**\n{evidence}",
        f"**Requested By**\n{interaction.user.mention}\n**Submitted:** <t:{unix_time}:F>",
    ]

    v2_payload = build_v2_payload(
        title=f"Moderation Request — {type.value}",
        body_text=None,
        inner_sections=sections,
    )
    # A Components V2 message can't have a top-level "content" field, so the
    # role/user ping is folded in as its own text-display component instead
    # (same approach used for ticket-open pings - see build_ticket_open_payload).
    v2_payload.insert(0, {"type": 10, "content": f"<@&{ping_role_id}>"})

    await interaction.client.http.request(
        discord.http.Route('POST', '/channels/{channel_id}/messages', channel_id=target_channel.id),
        json={"components": v2_payload, "flags": 32768},
    )

    await interaction.response.send_message(
        f"Your **{type.value}** moderation request for {user.mention} has been submitted to {target_channel.mention}.",
        ephemeral=True,
    )


# ============================================================
# --- GIVEAWAY SYSTEM (COMPONENTS V2) ---
#
# /giveaway            -> staff-only form (Hosted By / End Time / Description)
# "Enter" button       -> persistent, one entry per member, count updates live
# giveaway_sweep       -> checks every 10s; ends giveaways even after a restart
# Reroll Giveaway      -> right-click a giveaway message > Apps > Reroll Giveaway
#
# All state lives in giveaway_data.json (next to the other bot data files).
# The banner image must be saved as giveaway_banner.png next to this script.
# ============================================================

GIVEAWAY_DATA_FILE = "giveaway_data.json"
GIVEAWAY_BANNER_NAME = "giveaway_banner.png"
# Banner shown on every giveaway card. When this URL is set, the bot uses it
# directly and does not need giveaway_banner.png. Leave it as "" to fall back
# to uploading the local giveaway_banner.png file instead.
GIVEAWAY_BANNER_URL = "https://cdn.discordapp.com/attachments/1534314921322614859/1561924992512426045/image_11.png?ex=6ad81f81&is=6ad6ce01&hm=edec8a1ee9eebab8a6e6c7740b86b07acbc21a2443656e8b73940ffe6ea9bb66&"
# Channel that receives giveaway creation / entry / winner / reroll logs.
GIVEAWAY_LOG_CHANNEL_ID = 1561936262535839744
GIVEAWAY_MIN_SECONDS = 30
GIVEAWAY_MAX_SECONDS = 365 * 86400
GIVEAWAY_NO_MENTIONS = discord.AllowedMentions.none()


def giveaway_now() -> int:
    return int(central_now().timestamp())


def load_giveaway_data():
    data = load_json(GIVEAWAY_DATA_FILE, {"giveaways": {}})
    if not isinstance(data, dict):
        data = {"giveaways": {}}
    if not isinstance(data.get("giveaways"), dict):
        data["giveaways"] = {}
    return data


def save_giveaway_data(data):
    save_json(GIVEAWAY_DATA_FILE, data)


def find_giveaway_banner():
    """Locate giveaway_banner.png next to the script (or in the working folder)."""
    for base in (Path(__file__).resolve().parent, Path.cwd()):
        candidate = base / GIVEAWAY_BANNER_NAME
        if candidate.is_file():
            return candidate
    return None


def is_giveaway_manager(member) -> bool:
    """Authorized staff: Server Staff role or above (same rule as -purge), plus admins/owner."""
    return isinstance(member, discord.Member) and has_role_or_above(member, SERVER_STAFF_ROLE_ID)


def giveaway_timezone():
    return CENTRAL_TZ


_GIVEAWAY_REL_TOKEN = re.compile(
    r"(\d+)\s*(weeks?|wks?|w|days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s)(?![a-z])"
)
_GIVEAWAY_UNIT_SECONDS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
_GIVEAWAY_ABSOLUTE_FORMATS = (
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d %I:%M %p",
    "%Y-%m-%d %I:%M%p",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y %I:%M %p",
    "%m/%d/%Y %I:%M%p",
    "%m/%d/%y %H:%M",
    "%m/%d/%y %I:%M %p",
    "%m/%d/%y %I:%M%p",
    "%Y-%m-%d",
    "%m/%d/%Y",
)


def parse_giveaway_end_time(text: str) -> int:
    """Turn the End Time field into a unix timestamp.

    Accepted: durations ("30m", "2h", "1d 12h", "in 3 days"), a Discord
    timestamp (<t:1700000000>), a raw unix timestamp, or a date/time in
    Central Time ("12/25/2026 6:00 PM", "2026-12-25 18:00").
    Raises ValueError when the text can't be understood.
    """
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty")

    stamp = re.fullmatch(r"<t:(\d{9,12})(?::[a-zA-Z])?>", raw)
    if stamp:
        return int(stamp.group(1))
    if re.fullmatch(r"\d{9,12}", raw):
        return int(raw)

    # Relative durations.
    relative = re.sub(r"^in\s+", "", raw.lower())
    tokens = _GIVEAWAY_REL_TOKEN.findall(relative)
    if tokens:
        leftover = _GIVEAWAY_REL_TOKEN.sub("", relative)
        leftover = re.sub(r"\band\b|,", "", leftover).strip()
        if leftover == "":
            seconds = sum(int(n) * _GIVEAWAY_UNIT_SECONDS[unit[0]] for n, unit in tokens)
            return giveaway_now() + seconds

    # Absolute date/time (Central Time).
    cleaned = re.sub(r"\s*(cst|cdt|ct|central)$", "", raw, flags=re.IGNORECASE).strip()
    tz = giveaway_timezone()
    for fmt in _GIVEAWAY_ABSOLUTE_FORMATS:
        try:
            parsed = datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        return int(parsed.replace(tzinfo=tz).timestamp())

    raise ValueError("unrecognized time format")


def resolve_giveaway_host(guild: discord.Guild, text: str):
    """Return (display_text, user_id_or_None) for the Hosted By field."""
    value = (text or "").strip()
    match = re.fullmatch(r"<@!?(\d{15,20})>", value) or re.fullmatch(r"(\d{15,20})", value)
    if match:
        return f"<@{match.group(1)}>", int(match.group(1))

    wanted = value.lstrip("@").lower()
    if wanted:
        for member in guild.members:
            names = {member.name.lower(), member.display_name.lower()}
            if getattr(member, "global_name", None):
                names.add(member.global_name.lower())
            if wanted in names:
                return member.mention, member.id
    return value, None


def giveaway_winner_text(g: dict) -> str:
    if g.get("status") != "ended":
        return "Pending"
    if g.get("winner_id"):
        return f"<@{g['winner_id']}>"
    return "No valid entries"


class GiveawayEnterButton(discord.ui.Button):
    def __init__(self, ended: bool = False):
        super().__init__(
            label="Giveaway Ended" if ended else "Enter",
            style=discord.ButtonStyle.secondary,  # gray button
            custom_id="giveaway:enter",
            disabled=ended,
        )

    async def callback(self, interaction: discord.Interaction):
        await handle_giveaway_entry(interaction)


GIVEAWAY_DEFAULT_TITLE = "GVRG | Giveaway"


class GiveawayView(discord.ui.LayoutView):
    """Compact giveaway card: a Components V2 Container (no accent color = no sidebar)."""

    def __init__(self, giveaway: dict = None):
        super().__init__(timeout=None)
        g = giveaway or {}
        ended = g.get("status") == "ended"

        container = discord.ui.Container()  # accent_color intentionally unset

        end_ts = int(g.get("end_ts") or giveaway_now())
        title = (g.get("title") or GIVEAWAY_DEFAULT_TITLE).strip()

        # Smaller heading (###) + details. Winner sits directly under Entries.
        container.add_item(discord.ui.TextDisplay(
            f"### {title}\n"
            f"**Hosted By:** {g.get('host_text') or 'N/A'}\n"
            f"**End Time:** <t:{end_ts}:f> (<t:{end_ts}:R>)\n"
            f"**Entries:** {len(g.get('entries', {}))}\n"
            f"**Winner:** {giveaway_winner_text(g)}"
        ))

        container.add_item(discord.ui.Separator(spacing=discord.SeparatorSpacing.small))
        container.add_item(discord.ui.TextDisplay(g.get("description") or "No description provided."))

        # Banner image sits below the description.
        if g.get("has_banner"):
            gallery = discord.ui.MediaGallery()
            gallery.add_item(media=GIVEAWAY_BANNER_URL or f"attachment://{GIVEAWAY_BANNER_NAME}")
            container.add_item(gallery)

        # Enter button is the very last item, underneath the entire layout.
        row = discord.ui.ActionRow()
        row.add_item(GiveawayEnterButton(ended=ended))
        container.add_item(row)

        self.add_item(container)


async def log_giveaway(guild: discord.Guild, title: str, description: str, footer: str, color: int = 0x596744):
    """Send a giveaway event to the log channel without ever raising."""
    if guild is None:
        return
    try:
        await log_to_channel(
            bot=bot,
            guild=guild,
            channel_id=GIVEAWAY_LOG_CHANNEL_ID,
            title=title,
            description=description,
            color=color,
            footer_text=footer,
        )
    except Exception as exc:
        print(f"Giveaway log failed: {exc!r}")


async def handle_giveaway_entry(interaction: discord.Interaction):
    if interaction.message is None:
        return

    message_id = str(interaction.message.id)
    data = load_giveaway_data()
    g = data["giveaways"].get(message_id)

    if not g:
        await interaction.response.send_message(
            "This giveaway is no longer being tracked.", ephemeral=True
        )
        return

    # Entries close the moment the end time passes, even if the sweep hasn't run yet.
    if g.get("status") != "active" or giveaway_now() >= int(g.get("end_ts", 0)):
        await interaction.response.send_message(
            "This giveaway has ended and is no longer accepting entries.", ephemeral=True
        )
        return

    if interaction.user.bot:
        await interaction.response.send_message("Bots cannot enter giveaways.", ephemeral=True)
        return

    user_key = str(interaction.user.id)
    if user_key in g["entries"]:
        await interaction.response.send_message(
            "You have already entered this giveaway.", ephemeral=True
        )
        return

    # Record the entry (no awaits between load and save, so it can't interleave).
    g["entries"][user_key] = giveaway_now()
    save_giveaway_data(data)
    total = len(g["entries"])

    # Update the original message right away with the new count.
    await interaction.response.edit_message(view=GiveawayView(g))
    try:
        await interaction.followup.send(
            "You have been entered into the giveaway. Good luck!", ephemeral=True
        )
    except discord.HTTPException:
        pass

    await log_giveaway(
        interaction.guild,
        "Giveaway Entry",
        (
            f"**User:** {interaction.user.mention} (`{interaction.user.id}`)\n"
            f"**Giveaway:** {interaction.message.jump_url}\n"
            f"**Total Entries:** {total}"
        ),
        footer=f"Giveaway Entry | Message ID: {message_id}",
    )


async def pick_giveaway_winner(guild: discord.Guild, g: dict, exclude=()):
    """Randomly pick an eligible entrant: still in the server, not a bot, not excluded."""
    exclude = {int(x) for x in exclude}
    ids = [int(uid) for uid in g.get("entries", {}) if int(uid) not in exclude]
    random.shuffle(ids)

    for uid in ids:
        member = guild.get_member(uid)
        if member is None:
            try:
                member = await guild.fetch_member(uid)
            except (discord.NotFound, discord.HTTPException):
                continue
        if member.bot:
            continue
        return member
    return None


async def _fetch_giveaway_message(g: dict):
    """Return the giveaway message, or None if the channel/message no longer exists."""
    channel = bot.get_channel(int(g["channel_id"]))
    if channel is None:
        try:
            channel = await bot.fetch_channel(int(g["channel_id"]))
        except (discord.NotFound, discord.Forbidden):
            return None
    try:
        return await channel.fetch_message(int(g["message_id"]))
    except discord.NotFound:
        return None


async def sync_giveaway_message(message_id) -> bool:
    """Re-render the original giveaway message from stored data (entries/winner/ended state)."""
    data = load_giveaway_data()
    g = data["giveaways"].get(str(message_id))
    if not g:
        return False

    try:
        message = await _fetch_giveaway_message(g)
    except discord.HTTPException as exc:
        print(f"Giveaway {message_id}: could not fetch message: {exc!r}")
        return False

    if message is None:
        # The message was deleted - nothing left to update, stop retrying.
        g["synced"] = True
        save_giveaway_data(data)
        return False

    try:
        await message.edit(view=GiveawayView(g))
    except discord.HTTPException as exc:
        print(f"Giveaway {message_id}: message edit failed: {exc!r}")
        return False

    data = load_giveaway_data()
    latest = data["giveaways"].get(str(message_id))
    if latest is not None:
        latest["synced"] = True
        save_giveaway_data(data)
    return True


async def finish_giveaway(message_id, reroll: bool = False, actor=None):
    """End a giveaway (or reroll an ended one).

    Returns (code, winner_id) where code is one of:
    ok, not_found, not_ended, already_ended, no_candidates, missing
    """
    data = load_giveaway_data()
    g = data["giveaways"].get(str(message_id))
    if not g:
        return "not_found", None
    if reroll and g.get("status") != "ended":
        return "not_ended", None
    if not reroll and g.get("status") != "active":
        return "already_ended", None

    guild = bot.get_guild(int(g["guild_id"]))
    if guild is None:
        return "missing", None

    exclude = g.get("winner_history", []) if reroll else []
    winner = await pick_giveaway_winner(guild, g, exclude)

    if reroll and winner is None:
        return "no_candidates", None

    # Reload so nothing saved while we were picking gets overwritten.
    data = load_giveaway_data()
    g = data["giveaways"].get(str(message_id))
    if not g:
        return "not_found", None
    if not reroll and g.get("status") != "active":
        return "already_ended", None

    if not reroll:
        g["status"] = "ended"
        g["ended_at"] = giveaway_now()
    g["winner_id"] = winner.id if winner else None
    if winner:
        g.setdefault("winner_history", []).append(winner.id)
    g["synced"] = False
    save_giveaway_data(data)

    synced = await sync_giveaway_message(message_id)

    # Announce in the giveaway channel (this is the message that pings the winner).
    if synced:
        channel = bot.get_channel(int(g["channel_id"]))
        link = f"https://discord.com/channels/{g['guild_id']}/{g['channel_id']}/{g['message_id']}"
        try:
            if channel is not None:
                if winner:
                    prefix = "The giveaway was rerolled. " if reroll else ""
                    await channel.send(
                        f"{prefix}Congratulations {winner.mention}, you won the giveaway!\n{link}",
                        allowed_mentions=discord.AllowedMentions(users=[winner]),
                    )
                else:
                    await channel.send(
                        f"The giveaway ended with no valid entries.\n{link}",
                        allowed_mentions=GIVEAWAY_NO_MENTIONS,
                    )
        except discord.HTTPException as exc:
            print(f"Giveaway {message_id}: announcement failed: {exc!r}")

    if not reroll:
        await dm_giveaway_host(guild, g, winner)

    link = f"https://discord.com/channels/{g['guild_id']}/{g['channel_id']}/{g['message_id']}"
    await log_giveaway(
        guild,
        "Giveaway Rerolled" if reroll else "Giveaway Ended",
        (
            f"**Giveaway:** {link}\n"
            f"**Total Entries:** {len(g.get('entries', {}))}\n"
            f"**Winner:** {winner.mention if winner else 'No valid entries'}"
            + (f"\n**Rerolled By:** {actor.mention}" if actor else "")
        ),
        footer=f"Giveaway {'Reroll' if reroll else 'End'} | Message ID: {message_id}",
        color=0xCC3333 if reroll else 0x596744,
    )

    return "ok", (winner.id if winner else None)


async def dm_giveaway_host(guild: discord.Guild, g: dict, winner):
    """DM the host (or the staff member who created it) the full list of entrants."""
    entries = g.get("entries", {})
    ordered = sorted(entries.items(), key=lambda kv: kv[1])

    file_lines = [
        f"Giveaway: {g.get('title') or GIVEAWAY_DEFAULT_TITLE}",
        f"Server: {guild.name}",
        f"Total entries: {len(ordered)}",
        f"Winner: {winner} ({winner.id})" if winner else "Winner: No valid entries",
        "",
        "Entrants (in order of entry):",
    ]
    mentions = []
    for index, (uid, ts) in enumerate(ordered, start=1):
        member = guild.get_member(int(uid))
        label = f"{member} ({uid})" if member else f"Left the server ({uid})"
        entered = datetime.fromtimestamp(int(ts), CENTRAL_TZ).strftime("%Y-%m-%d %I:%M:%S %p %Z")
        file_lines.append(f"{index}. {label} - entered {entered}")
        mentions.append(f"<@{uid}>")

    link = f"https://discord.com/channels/{g['guild_id']}/{g['channel_id']}/{g['message_id']}"
    content = (
        f"Your giveaway **{g.get('title') or GIVEAWAY_DEFAULT_TITLE}** in **{guild.name}** has ended.\n"
        f"**Total Entries:** {len(ordered)}\n"
        f"**Winner:** {winner.mention if winner else 'No valid entries'}\n"
        f"{link}"
    )
    inline = ", ".join(mentions)
    if mentions and len(content) + len(inline) + 30 < 1900:
        content += f"\n\n**Entrants:** {inline}"
    content += "\n\nThe full list is attached."

    targets = []
    for candidate in (g.get("host_id"), g.get("created_by")):
        if candidate and int(candidate) not in targets:
            targets.append(int(candidate))

    for user_id in targets:
        try:
            user = await bot.fetch_user(user_id)
            attachment = discord.File(
                io.BytesIO("\n".join(file_lines).encode("utf-8")),
                filename=f"giveaway-{g['message_id']}-entrants.txt",
            )
            await user.send(content=content, file=attachment, allowed_mentions=GIVEAWAY_NO_MENTIONS)
            return True
        except (discord.Forbidden, discord.NotFound, discord.HTTPException) as exc:
            print(f"Giveaway {g.get('message_id')}: could not DM {user_id}: {exc!r}")
    return False


@tasks.loop(seconds=10)
async def giveaway_sweep():
    """Ends due giveaways (also catches ones that expired while the bot was offline)
    and retries any winner/entry update that previously failed to reach Discord."""
    data = load_giveaway_data()
    now = giveaway_now()

    for message_id, g in list(data["giveaways"].items()):
        try:
            if g.get("status") == "active" and now >= int(g.get("end_ts", 0)):
                await finish_giveaway(message_id)
            elif g.get("status") == "ended" and g.get("synced") is False:
                await sync_giveaway_message(message_id)
        except Exception as exc:
            print(f"Giveaway sweep error for {message_id}: {exc!r}")


@giveaway_sweep.before_loop
async def before_giveaway_sweep():
    await bot.wait_until_ready()


class GiveawayCreateModal(discord.ui.Modal, title="Create Giveaway"):
    giveaway_title = discord.ui.TextInput(
        label="Giveaway Title",
        placeholder="Leave blank for the default: GVRG | Giveaway",
        required=False,
        max_length=100,
    )
    hosted_by = discord.ui.TextInput(
        label="Hosted By",
        placeholder="@User, username, or user ID",
        required=True,
        max_length=100,
    )
    end_time = discord.ui.TextInput(
        label="End Time",
        placeholder="e.g. 2h, 1d 12h, or 12/25/2026 6:00 PM (Central)",
        required=True,
        max_length=60,
    )
    description = discord.ui.TextInput(
        label="Description",
        style=discord.TextStyle.paragraph,
        placeholder="Describe the giveaway and its prize.",
        required=True,
        max_length=1500,
    )

    def __init__(self, default_host: str = ""):
        super().__init__()
        if default_host:
            self.hosted_by.default = default_host

    async def on_submit(self, interaction: discord.Interaction):
        try:
            end_ts = parse_giveaway_end_time(self.end_time.value)
        except ValueError:
            await interaction.response.send_message(
                "I couldn't understand that End Time. Use a duration like `30m`, `2h`, `1d 12h`, "
                "or a Central Time date like `12/25/2026 6:00 PM` or `2026-12-25 18:00`.",
                ephemeral=True,
            )
            return

        seconds_left = end_ts - giveaway_now()
        if seconds_left < GIVEAWAY_MIN_SECONDS:
            await interaction.response.send_message(
                "The End Time must be at least 30 seconds in the future.", ephemeral=True
            )
            return
        if seconds_left > GIVEAWAY_MAX_SECONDS:
            await interaction.response.send_message(
                "The End Time can be at most 1 year away.", ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True)

        host_text, host_id = resolve_giveaway_host(interaction.guild, self.hosted_by.value)
        banner_path = None if GIVEAWAY_BANNER_URL else find_giveaway_banner()
        has_banner = bool(GIVEAWAY_BANNER_URL) or banner_path is not None

        g = {
            "message_id": None,
            "channel_id": interaction.channel_id,
            "guild_id": interaction.guild.id,
            "title": " ".join((self.giveaway_title.value or "").split()) or GIVEAWAY_DEFAULT_TITLE,
            "host_text": host_text,
            "host_id": host_id,
            "created_by": interaction.user.id,
            "description": self.description.value.strip(),
            "end_ts": end_ts,
            "created_at": giveaway_now(),
            "status": "active",
            "entries": {},
            "winner_id": None,
            "winner_history": [],
            "has_banner": has_banner,
            "synced": True,
        }

        send_kwargs = {"view": GiveawayView(g), "allowed_mentions": GIVEAWAY_NO_MENTIONS}
        if banner_path is not None:
            send_kwargs["file"] = discord.File(banner_path, filename=GIVEAWAY_BANNER_NAME)
        elif not GIVEAWAY_BANNER_URL:
            print(f"Warning: {GIVEAWAY_BANNER_NAME} was not found; posting the giveaway without a banner.")

        try:
            message = await interaction.channel.send(**send_kwargs)
        except discord.Forbidden:
            await interaction.followup.send(
                "I don't have permission to send messages (or attach files) in this channel.",
                ephemeral=True,
            )
            return
        except discord.HTTPException as exc:
            print(f"Giveaway post failed: {exc!r}")
            await interaction.followup.send(
                "Discord rejected the giveaway message. Please try again.", ephemeral=True
            )
            return

        g["message_id"] = message.id
        data = load_giveaway_data()
        data["giveaways"][str(message.id)] = g
        save_giveaway_data(data)

        await log_giveaway(
            interaction.guild,
            "Giveaway Created",
            (
                f"**Giveaway:** {message.jump_url}\n"
                f"**Title:** {g['title']}\n"
                f"**Hosted By:** {host_text}\n"
                f"**Created By:** {interaction.user.mention}\n"
                f"**Ends:** <t:{end_ts}:F> (<t:{end_ts}:R>)\n"
                f"**Description:** {g['description'][:900]}"
            ),
            footer=f"Giveaway Created | Message ID: {message.id}",
        )

        await interaction.followup.send(
            f"Giveaway posted: {message.jump_url}\nIt will end <t:{end_ts}:R>.",
            ephemeral=True,
        )

    async def on_error(self, interaction: discord.Interaction, error: Exception):
        print(f"Giveaway modal error: {error!r}")
        traceback.print_exception(type(error), error, error.__traceback__)
        try:
            if interaction.response.is_done():
                await interaction.followup.send("Something went wrong creating the giveaway.", ephemeral=True)
            else:
                await interaction.response.send_message("Something went wrong creating the giveaway.", ephemeral=True)
        except discord.HTTPException:
            pass


@bot.tree.command(name="giveaway", description="Create a giveaway in this channel.")
async def giveaway_cmd(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("This command can only be used inside a server.", ephemeral=True)
        return
    if not is_giveaway_manager(interaction.user):
        await interaction.response.send_message("You are not authorized to create giveaways.", ephemeral=True)
        return
    await interaction.response.send_modal(
        GiveawayCreateModal(default_host=interaction.user.display_name)
    )


@app_commands.context_menu(name="Reroll Giveaway")
async def reroll_giveaway_menu(interaction: discord.Interaction, message: discord.Message):
    if interaction.guild is None:
        await interaction.response.send_message("This can only be used inside a server.", ephemeral=True)
        return
    data = load_giveaway_data()
    g = data["giveaways"].get(str(message.id))
    if not g:
        await interaction.response.send_message("That message is not a giveaway.", ephemeral=True)
        return
    if g.get("status") != "ended":
        await interaction.response.send_message(
            "That giveaway hasn't ended yet. You can reroll it once it has ended.", ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)
    code, winner_id = await finish_giveaway(message.id, reroll=True, actor=interaction.user)

    if code == "ok":
        await interaction.followup.send(f"Giveaway rerolled. New winner: <@{winner_id}>.", ephemeral=True)
    elif code == "no_candidates":
        await interaction.followup.send(
            "There are no other eligible entrants to reroll. The current winner was kept.", ephemeral=True
        )
    else:
        await interaction.followup.send("The giveaway could not be rerolled right now. Please try again.", ephemeral=True)


# ============================================================
# --- STAFF OF THE MONTH (/sotm) ---
#
# /sotm month:<month> ends:<when>
#                    -> posts a Components V2 poll for the month you pick (dropdown
#                       of all 12 months) listing every member who has
#                       one of SOTM_ROLE_IDS and none of SOTM_EXCLUDED_ROLE_IDS
#                       (High Command and one other role are never listed). "ends" is either a duration for
#                       testing (30s, 10m, 2h, 3d) or a Central Time date
#                       (11/01/2026 = midnight starting Nov 1, or 11/01/2026 6:00 PM).
# Dropdowns          -> persistent; one vote per member (re-voting replaces the old
#                       vote). Staff and Verified Members may vote; voting for
#                       yourself is rejected.
# "Vote Count" button -> anyone can click it for a private, live list of every
#                       eligible staff member and their current vote total.
# sotm_sweep         -> checks every 5s; closes due polls (even ones that expired
#                       while the bot was offline), shows the final result on the
#                       poll message and announces the winner.
# /sotm-member <user> -> staff-only: gives the Staff of the Month role (SOTM_MEMBER_ROLE_ID) to one member and removes it from everyone else.
# /sotm-results      -> staff-only: pick a poll (if more than one), then see its tally and who voted for whom.
#                       Active polls have a Delete Poll button (status becomes "deleted": hidden, no more votes).
#                       A poll whose message is deleted in Discord is marked deleted automatically.
#
# All dates/times use America/Chicago (CST/CDT handled automatically).
# State lives in sotm_data.json (next to the other bot data files).
# ============================================================

SOTM_DATA_FILE = "sotm_data.json"
SOTM_ROLE_IDS = {1543131387991949403, 1532456149901639791}   # eligible staff (listed in the poll)
SOTM_VOTER_ROLE_IDS = {1533960357155049675}                   # extra role(s) allowed to vote
# Anyone holding one of these roles is never listed as a nominee, even if they also have an eligible role.
SOTM_EXCLUDED_ROLE_IDS = {
    1536260044977340536,   # High Command
    1543133179286655066,   # additional excluded role
}


def sotm_is_excluded(member) -> bool:
    """True if the member holds a role that bars them from Staff of the Month nominations."""
    return any(r.id in SOTM_EXCLUDED_ROLE_IDS for r in member.roles)
SOTM_OPTIONS_PER_SELECT = 25    # Discord limit per dropdown
SOTM_MAX_SELECTS = 10           # keeps the message under the 40-component limit
SOTM_MIN_SECONDS = 30
SOTM_MAX_SECONDS = 365 * 86400
SOTM_MONTH_NAMES = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]
SOTM_SELF_VOTE_MESSAGE = "You cannot vote for yourself. Please choose someone else."
_sotm_finish_lock = asyncio.Lock()


def sotm_month_name(now: datetime = None) -> str:
    """Current month name in Central Time (updates automatically with the date)."""
    now = now or central_now()
    return SOTM_MONTH_NAMES[now.month - 1]


def sotm_description(month: str) -> str:
    return (
        f"Please choose a Staff of The Month for {month}. "
        "Staff Members may not choose themselves."
    )


def sotm_format_central(ts: int) -> str:
    """e.g. 'November 1, 2026 at 12:00 AM CDT' (always Central Time, CST/CDT automatic)."""
    dt = datetime.fromtimestamp(int(ts), CENTRAL_TZ)
    clock = dt.strftime("%I:%M:%S %p" if dt.second else "%I:%M %p").lstrip("0")
    return f"{dt:%B} {dt.day}, {dt.year} at {clock} {dt:%Z}"


def load_sotm_data():
    data = load_json(SOTM_DATA_FILE, {"polls": {}})
    if not isinstance(data, dict):
        data = {"polls": {}}
    if not isinstance(data.get("polls"), dict):
        data["polls"] = {}
    return data


def save_sotm_data(data):
    save_json(SOTM_DATA_FILE, data)


def sotm_can_vote(member) -> bool:
    """Staff (either SOTM role) or anyone with a voter role may vote."""
    allowed = SOTM_ROLE_IDS | SOTM_VOTER_ROLE_IDS
    return isinstance(member, discord.Member) and any(r.id in allowed for r in member.roles)


def sotm_tally(poll: dict) -> dict:
    tally = {}
    for chosen in poll.get("votes", {}).values():
        tally[int(chosen)] = tally.get(int(chosen), 0) + 1
    return tally


def sotm_winner_text(poll: dict) -> str:
    winners = poll.get("winner_ids") or []
    if not winners:
        return "No votes were cast"
    mentions = ", ".join(f"<@{w}>" for w in winners)
    return f"Tie: {mentions}" if len(winners) > 1 else mentions


def sotm_results_pages(poll: dict) -> list:
    """Live results text: every eligible staff member with their current vote count.

    Built from the saved poll data each time, so it always reflects the latest votes.
    Returned as pages that fit Discord's 2000-character message limit.
    """
    tally = sotm_tally(poll)
    rows = [
        (int(c["id"]), str(c["name"]), tally.get(int(c["id"]), 0))
        for c in poll.get("candidates", [])
    ]
    rows.sort(key=lambda r: (-r[2], r[1].lower()))

    lines, last_count, rank = [], None, 0
    for position, (uid, _name, count) in enumerate(rows, start=1):
        if count != last_count:
            rank, last_count = position, count
        lines.append(f"**{rank}.** <@{uid}> — **{count}** vote{'s' if count != 1 else ''}")

    if poll.get("status") == "closed":
        status = "Final results"
    elif poll.get("end_ts"):
        status = f"Voting ends {sotm_format_central(poll['end_ts'])}"
    else:
        status = "Voting is open"
    header = (
        f"**Staff of the Month — {poll.get('month', '')}**\n"
        f"{status}\n"
        f"**Total Votes:** {len(poll.get('votes', {}))}\n"
    )

    pages, current = [], header
    for line in lines or ["No eligible staff members."]:
        if len(current) + len(line) + 1 > 1900:
            pages.append(current)
            current = ""
        current += "\n" + line
    pages.append(current)
    return pages


async def handle_sotm_results(interaction: discord.Interaction):
    if interaction.message is None:
        return
    poll = load_sotm_data()["polls"].get(str(interaction.message.id))
    if not poll or poll.get("status") == "deleted":
        await interaction.response.send_message(
            "This poll is no longer being tracked.", ephemeral=True
        )
        return

    pages = sotm_results_pages(poll)
    no_mentions = discord.AllowedMentions.none()
    await interaction.response.send_message(pages[0], ephemeral=True, allowed_mentions=no_mentions)
    for page in pages[1:]:
        try:
            await interaction.followup.send(page, ephemeral=True, allowed_mentions=no_mentions)
        except discord.HTTPException:
            break


class SotmResultsButton(discord.ui.Button):
    def __init__(self):
        super().__init__(
            label="Vote Count",
            style=discord.ButtonStyle.secondary,
            custom_id="sotm:results",
        )

    async def callback(self, interaction: discord.Interaction):
        await handle_sotm_results(interaction)


class SotmSelect(discord.ui.Select):
    def __init__(self, index: int, total: int, candidates: list):
        options = [
            discord.SelectOption(
                label=str(c["name"])[:100] or str(c["id"]),
                value=str(c["id"]),
                description=(f"@{c['username']}" if c.get("username") else None),
            )
            for c in candidates
        ]
        placeholder = "Choose a staff member..."
        if total > 1:
            placeholder = f"Choose a staff member... ({index + 1}/{total})"
        super().__init__(
            placeholder=placeholder,
            min_values=1,
            max_values=1,
            options=options,
            custom_id=f"sotm:vote:{index}",
        )

    async def callback(self, interaction: discord.Interaction):
        await handle_sotm_vote(interaction, int(self.values[0]))


class SotmView(discord.ui.LayoutView):
    """Staff of the Month poll card (Components V2 container, no accent color)."""

    def __init__(self, poll: dict):
        super().__init__(timeout=None)
        month = poll.get("month") or sotm_month_name()
        candidates = poll.get("candidates", [])
        closed = poll.get("status") == "closed"
        end_ts = poll.get("end_ts")

        container = discord.ui.Container()
        container.add_item(discord.ui.TextDisplay(f"# Staff of the Month — {month}"))
        container.add_item(discord.ui.TextDisplay(sotm_description(month)))

        if end_ts:
            label = "Voting Ended" if closed else "Voting Ends"
            container.add_item(discord.ui.TextDisplay(
                f"**{label}:** {sotm_format_central(end_ts)}"
                + ("" if closed else f" (<t:{int(end_ts)}:R>)")
            ))
        container.add_item(discord.ui.Separator())

        if closed:
            container.add_item(discord.ui.TextDisplay(
                f"**Winner:** {sotm_winner_text(poll)}\n"
                f"**Votes Cast:** {len(poll.get('votes', {}))}\n"
                f"-# Voting has ended. {FOOTER_TEXT}"
            ))
            button_row = discord.ui.ActionRow()
            button_row.add_item(SotmResultsButton())
            container.add_item(button_row)
        else:
            chunks = [
                candidates[i:i + SOTM_OPTIONS_PER_SELECT]
                for i in range(0, len(candidates), SOTM_OPTIONS_PER_SELECT)
            ]
            for index, chunk in enumerate(chunks):
                row = discord.ui.ActionRow()
                row.add_item(SotmSelect(index, len(chunks), chunk))
                container.add_item(row)
            container.add_item(discord.ui.Separator())
            container.add_item(discord.ui.TextDisplay(
                f"**Votes Cast:** {len(poll.get('votes', {}))}\n-# {FOOTER_TEXT}"
            ))
            button_row = discord.ui.ActionRow()
            button_row.add_item(SotmResultsButton())
            container.add_item(button_row)
        self.add_item(container)


async def _sotm_refresh_and_reply(interaction: discord.Interaction, poll: dict, text: str):
    """Re-render the poll (resets the dropdown + updates the count), then reply privately."""
    try:
        await interaction.response.edit_message(view=SotmView(poll))
        await interaction.followup.send(text, ephemeral=True)
    except discord.HTTPException as exc:
        print(f"SOTM: could not refresh poll message: {exc!r}")
        try:
            if interaction.response.is_done():
                await interaction.followup.send(text, ephemeral=True)
            else:
                await interaction.response.send_message(text, ephemeral=True)
        except discord.HTTPException:
            pass


def sotm_poll_is_open(poll: dict) -> bool:
    if poll.get("status", "active") != "active":
        return False
    end_ts = poll.get("end_ts")
    return not (end_ts and giveaway_now() >= int(end_ts))


async def handle_sotm_vote(interaction: discord.Interaction, chosen_id: int):
    if interaction.message is None or interaction.guild is None:
        return

    data = load_sotm_data()
    poll = data["polls"].get(str(interaction.message.id))
    if not poll:
        await interaction.response.send_message(
            "This poll is no longer being tracked.", ephemeral=True
        )
        return

    if poll.get("status") == "deleted":
        await interaction.response.send_message(
            "This poll has been deleted and is no longer accepting votes.", ephemeral=True
        )
        return

    # Votes close the moment the end time passes, even if the sweep hasn't run yet.
    if not sotm_poll_is_open(poll):
        await interaction.response.send_message(
            "Voting for this poll has ended.", ephemeral=True
        )
        return

    voter = interaction.user

    # Only staff and members with a voter role may vote.
    if not sotm_can_vote(voter):
        await interaction.response.send_message(
            "You do not have permission to vote in this poll.", ephemeral=True
        )
        return

    # Self-votes are rejected here, server-side, regardless of what the client sent.
    if chosen_id == voter.id:
        await _sotm_refresh_and_reply(interaction, poll, SOTM_SELF_VOTE_MESSAGE)
        return

    candidate = next((c for c in poll.get("candidates", []) if int(c["id"]) == chosen_id), None)
    if candidate is None:
        await interaction.response.send_message(
            "That staff member is not part of this poll.", ephemeral=True
        )
        return

    # Excluded members (e.g. High Command) can't receive votes, even in a poll that was posted before they were excluded.
    chosen_member = interaction.guild.get_member(chosen_id)
    if chosen_member is not None and sotm_is_excluded(chosen_member):
        await interaction.response.send_message(
            "That staff member is not eligible for Staff of the Month.", ephemeral=True
        )
        return

    # Record the vote (no awaits between load and save, so it can't interleave).
    votes = poll.setdefault("votes", {})
    changed = str(voter.id) in votes
    votes[str(voter.id)] = chosen_id
    save_sotm_data(data)

    text = (
        f"Your vote has been changed to **{candidate['name']}**."
        if changed else f"Your vote for **{candidate['name']}** has been recorded."
    )
    await _sotm_refresh_and_reply(interaction, poll, text)


# ---------- closing / winner announcement ----------

async def _fetch_sotm_message(poll: dict):
    """Return the poll message, or None if the channel/message no longer exists."""
    channel = bot.get_channel(int(poll["channel_id"]))
    if channel is None:
        try:
            channel = await bot.fetch_channel(int(poll["channel_id"]))
        except (discord.NotFound, discord.Forbidden):
            return None, None
    try:
        return channel, await channel.fetch_message(int(poll["message_id"]))
    except discord.NotFound:
        return channel, None


async def finish_sotm_poll(message_id) -> bool:
    """Close a poll, finalize the result, update the card and announce the winner.

    Safe to call repeatedly: the result is locked in once, and the card update /
    announcement is retried by the sweep until it succeeds.
    """
    async with _sotm_finish_lock:
        data = load_sotm_data()
        poll = data["polls"].get(str(message_id))
        if not poll or poll.get("status") == "deleted":
            return False

        if poll.get("status", "active") == "active":
            # Finalize the result exactly once (no awaits between load and save).
            tally = sotm_tally(poll)
            top = max(tally.values()) if tally else 0
            poll["winner_ids"] = sorted(uid for uid, n in tally.items() if n == top) if top else []
            poll["final_tally"] = {str(uid): n for uid, n in tally.items()}
            poll["winner_votes"] = top
            poll["status"] = "closed"
            poll["closed_at"] = giveaway_now()
            poll["announced"] = False
            save_sotm_data(data)
        elif poll.get("announced"):
            return True

        try:
            channel, message = await _fetch_sotm_message(poll)
        except discord.HTTPException as exc:
            print(f"SOTM {message_id}: could not fetch message: {exc!r}")
            return False

        if message is not None:
            try:
                await message.edit(view=SotmView(poll))
            except discord.HTTPException as exc:
                print(f"SOTM {message_id}: message edit failed: {exc!r}")
                return False

        if channel is not None:
            month = poll.get("month", "")
            winners = poll.get("winner_ids") or []
            link = f"https://discord.com/channels/{poll['guild_id']}/{poll['channel_id']}/{poll['message_id']}"
            top = int(poll.get("winner_votes", 0))
            plural = "s" if top != 1 else ""
            if not winners:
                text = (
                    f"Voting for **Staff of the Month — {month}** has ended, "
                    f"but no votes were cast.\n{link}"
                )
            elif len(winners) == 1:
                text = (
                    f"Voting for **Staff of the Month — {month}** has ended!\n"
                    f"Congratulations <@{winners[0]}>, you are the Staff of the Month "
                    f"with **{top}** vote{plural}!\n{link}"
                )
            else:
                names = ", ".join(f"<@{w}>" for w in winners)
                text = (
                    f"Voting for **Staff of the Month — {month}** has ended in a tie!\n"
                    f"{names} each received **{top}** vote{plural}.\n{link}"
                )
            try:
                await channel.send(
                    text,
                    allowed_mentions=discord.AllowedMentions(
                        users=[discord.Object(id=int(w)) for w in winners]
                    ),
                )
            except discord.Forbidden:
                print(f"SOTM {message_id}: missing permission to announce in channel {poll['channel_id']}.")
            except discord.HTTPException as exc:
                print(f"SOTM {message_id}: announcement failed: {exc!r}")
                return False

        data = load_sotm_data()
        latest = data["polls"].get(str(message_id))
        if latest is not None:
            latest["announced"] = True
            save_sotm_data(data)
        return True


@tasks.loop(seconds=5)
async def sotm_sweep():
    """Closes due polls (also catches ones that expired while the bot was offline)
    and retries any card update / announcement that previously failed."""
    data = load_sotm_data()
    now = giveaway_now()

    for message_id, poll in list(data["polls"].items()):
        try:
            status = poll.get("status", "active")
            if status == "active" and poll.get("end_ts") and now >= int(poll["end_ts"]):
                await finish_sotm_poll(message_id)
            elif status == "closed" and poll.get("announced") is False:
                await finish_sotm_poll(message_id)
        except Exception as exc:
            print(f"SOTM sweep error for {message_id}: {exc!r}")


@sotm_sweep.before_loop
async def before_sotm_sweep():
    await bot.wait_until_ready()


# ---------- commands ----------

def sotm_collect_candidates(guild: discord.Guild) -> list:
    members = [
        m for m in guild.members
        if not m.bot
        and any(r.id in SOTM_ROLE_IDS for r in m.roles)
        and not sotm_is_excluded(m)
    ]
    members.sort(key=lambda m: (m.display_name.lower(), m.id))
    return [{"id": m.id, "name": m.display_name, "username": m.name} for m in members]


@bot.tree.command(name="sotm", description="Start the Staff of the Month poll.")
@app_commands.describe(
    month="The month this Staff of the Month poll is for.",
    ends="When voting ends: a duration (30s, 10m, 2h, 3d) or a Central Time date (11/01/2026 or 11/01/2026 6:00 PM).",
)
@app_commands.choices(
    month=[app_commands.Choice(name=m, value=m) for m in SOTM_MONTH_NAMES]
)
async def sotm_cmd(interaction: discord.Interaction, month: app_commands.Choice[str], ends: str):
    if interaction.guild is None:
        await interaction.response.send_message("This command can only be used inside a server.", ephemeral=True)
        return
    if not is_giveaway_manager(interaction.user):
        await interaction.response.send_message("You are not authorized to start this poll.", ephemeral=True)
        return

    # Parse the deadline first so a bad value is reported before anything is posted.
    try:
        end_ts = parse_giveaway_end_time(ends)
    except ValueError:
        await interaction.response.send_message(
            "I couldn't understand that end time. Use a duration like `30s`, `10m`, `2h`, `3d`, "
            "or a Central Time date like `11/01/2026` or `11/01/2026 6:00 PM`.",
            ephemeral=True,
        )
        return

    seconds_left = end_ts - giveaway_now()
    # Small allowance so "30s" isn't rejected by the time it takes to parse.
    if seconds_left < SOTM_MIN_SECONDS - 3:
        await interaction.response.send_message(
            "The end time must be at least 30 seconds in the future.", ephemeral=True
        )
        return
    if seconds_left > SOTM_MAX_SECONDS:
        await interaction.response.send_message(
            "The end time can be at most 1 year away.", ephemeral=True
        )
        return

    await interaction.response.defer(ephemeral=True)

    guild = interaction.guild
    # Make sure the member cache is complete so every eligible staff member is listed.
    if not guild.chunked:
        try:
            await guild.chunk()
        except Exception as exc:
            print(f"SOTM: guild.chunk() failed: {exc!r}")

    candidates = sotm_collect_candidates(guild)
    if not candidates:
        await interaction.followup.send(
            "No members were found with the Staff of the Month roles.", ephemeral=True
        )
        return
    if len(candidates) > SOTM_OPTIONS_PER_SELECT * SOTM_MAX_SELECTS:
        await interaction.followup.send(
            f"There are {len(candidates)} eligible staff members, which is more than one poll can "
            f"hold ({SOTM_OPTIONS_PER_SELECT * SOTM_MAX_SELECTS}).",
            ephemeral=True,
        )
        return

    now = central_now()
    poll = {
        "message_id": None,
        "channel_id": interaction.channel_id,
        "guild_id": guild.id,
        "month": month.value,
        "year": now.year,
        "created_by": interaction.user.id,
        "created_at": int(now.timestamp()),
        "end_ts": end_ts,
        "status": "active",
        "candidates": candidates,
        "votes": {},
        "winner_ids": [],
        "announced": False,
    }

    try:
        message = await interaction.channel.send(
            view=SotmView(poll), allowed_mentions=discord.AllowedMentions.none()
        )
    except discord.Forbidden:
        await interaction.followup.send(
            "I don't have permission to send messages in this channel.", ephemeral=True
        )
        return
    except discord.HTTPException as exc:
        print(f"SOTM post failed: {exc!r}")
        await interaction.followup.send("Discord rejected the poll message. Please try again.", ephemeral=True)
        return

    poll["message_id"] = message.id
    data = load_sotm_data()
    data["polls"][str(message.id)] = poll
    save_sotm_data(data)

    # Make this poll's dropdowns work immediately (and after restarts via load_runtime_components).
    try:
        bot.add_view(SotmView(poll), message_id=message.id)
    except Exception as exc:
        print(f"SOTM: could not register poll view: {exc!r}")

    await interaction.followup.send(
        f"Staff of the Month poll posted: {message.jump_url}\n"
        f"**Month:** {month.value}\n"
        f"**{len(candidates)}** staff members are listed.\n"
        f"Voting ends {sotm_format_central(end_ts)} (<t:{end_ts}:R>).",
        ephemeral=True,
    )


def sotm_results_embed(poll: dict) -> discord.Embed:
    """The vote tally embed for one poll (same design as before)."""
    tally = sotm_tally(poll)

    names = {int(c["id"]): c["name"] for c in poll.get("candidates", [])}
    ranked = sorted(tally.items(), key=lambda kv: (-kv[1], names.get(kv[0], "").lower()))

    lines = [
        f"**#{rank}** <@{uid}> ({names.get(uid, uid)}) \u2014 **{count}** vote{'s' if count != 1 else ''}"
        for rank, (uid, count) in enumerate(ranked, start=1)
    ]
    closed = poll.get("status") == "closed"
    end_ts = poll.get("end_ts")
    footer = f"Total votes: {len(poll.get('votes', {}))} | " + (
        "Final result" if closed else "Voting still open"
    )
    if end_ts:
        footer += f" | {'Ended' if closed else 'Ends'} {sotm_format_central(end_ts)}"
    embed = discord.Embed(
        title=f"Staff of the Month \u2014 {poll.get('month', '')} " + ("Final Results" if closed else "Results So Far"),
        description="\n".join(lines)[:4000] if lines else "No votes have been cast yet.",
        color=0x596744,
    )
    embed.set_footer(text=footer)
    return embed


def sotm_vote_detail_embeds(poll: dict, guild: discord.Guild) -> list:
    """Who each person voted for, read only from THIS poll's own vote record.

    Returned as one or more embeds so a large poll never exceeds Discord's size limits.
    """
    votes = poll.get("votes", {})
    poll_link = None
    if poll.get("message_id") and poll.get("channel_id"):
        poll_link = f"https://discord.com/channels/{guild.id}/{poll['channel_id']}/{poll['message_id']}"

    header = f"**Poll:** {poll_link}\n" if poll_link else ""
    header += f"**Total Votes:** {len(votes)}\n"
    title = f"Staff of the Month \u2014 {poll.get('month', '')} Individual Votes"

    def voter_sort_key(row):
        member = guild.get_member(row[0])
        return ((member.display_name if member else "").lower(), row[0])

    rows = sorted(((int(v), int(c)) for v, c in votes.items()), key=voter_sort_key)
    lines = [f"<@{voter}> voted for <@{choice}>" for voter, choice in rows]
    if not lines:
        lines = ["No votes have been cast yet."]

    pages, current = [], header
    for line in lines:
        if len(current) + len(line) + 1 > 3800:
            pages.append(current)
            current = ""
        current += "\n" + line
    pages.append(current)

    embeds = []
    for i, text in enumerate(pages, start=1):
        embed = discord.Embed(title=title, description=text, color=0x596744)
        if len(pages) > 1:
            embed.set_footer(text=f"Page {i} of {len(pages)}")
        embeds.append(embed)
    return embeds


async def sotm_message_missing(poll: dict) -> bool:
    """True if the poll's message no longer exists in Discord (e.g. it was deleted by hand)."""
    try:
        _channel, message = await asyncio.wait_for(_fetch_sotm_message(poll), timeout=2.0)
    except Exception:
        return False  # can't tell, so don't claim it is missing
    return message is None


SOTM_MESSAGE_MISSING_NOTE = (
    "The message for this poll no longer exists in Discord. "
    "Use Delete Poll to remove it from the active poll list."
)


async def _sotm_send_results(interaction: discord.Interaction, poll: dict, key, edit: bool = False):
    """Show one poll's tally, then its individual votes (all private to the person who asked).

    Active polls also get a Delete Poll button.
    """
    embed = sotm_results_embed(poll)
    kwargs = {"embed": embed}
    if poll.get("status", "active") == "active":
        note = SOTM_MESSAGE_MISSING_NOTE if await sotm_message_missing(poll) else None
        kwargs["content"] = note
        kwargs["view"] = SotmPollActionView(interaction.user.id, str(key), note)
    elif edit:
        kwargs["content"] = None
        kwargs["view"] = None

    if edit:
        await interaction.response.edit_message(**kwargs)
    else:
        await interaction.response.send_message(
            ephemeral=True, allowed_mentions=discord.AllowedMentions.none(), **kwargs
        )
    for page in sotm_vote_detail_embeds(poll, interaction.guild):
        try:
            await interaction.followup.send(
                embed=page, ephemeral=True, allowed_mentions=discord.AllowedMentions.none()
            )
        except discord.HTTPException:
            break


async def sotm_delete_poll(message_id, deleted_by) -> str:
    """Delete an ACTIVE poll: mark it deleted (so it is no longer active and rejects votes), then
    remove its message from Discord if it still exists.

    Returns one of: "not_found", "not_active", "message_deleted", "message_gone", "message_failed".
    The poll's saved record is kept (with status "deleted") but it no longer appears anywhere.
    """
    async with _sotm_finish_lock:
        data = load_sotm_data()
        poll = data["polls"].get(str(message_id))
        if not poll or poll.get("status") == "deleted":
            return "not_found"
        if poll.get("status", "active") != "active":
            return "not_active"
        poll["status"] = "deleted"
        poll["deleted_at"] = giveaway_now()
        poll["deleted_by"] = deleted_by
        save_sotm_data(data)

    try:
        _channel, message = await _fetch_sotm_message(poll)
    except discord.HTTPException as exc:
        print(f"SOTM {message_id}: could not look up the poll message to delete it: {exc!r}")
        return "message_failed"
    if message is None:
        return "message_gone"
    try:
        await message.delete()
        return "message_deleted"
    except discord.NotFound:
        return "message_gone"
    except discord.HTTPException as exc:
        print(f"SOTM {message_id}: could not delete the poll message: {exc!r}")
        return "message_failed"


async def sotm_mark_message_deleted(message_id: int):
    """A poll message was deleted in Discord: stop treating its poll as active."""
    if str(message_id) not in load_sotm_data()["polls"]:
        return
    async with _sotm_finish_lock:
        data = load_sotm_data()
        poll = data["polls"].get(str(message_id))
        if poll and poll.get("status", "active") == "active":
            poll["status"] = "deleted"
            poll["deleted_at"] = giveaway_now()
            poll["deleted_by"] = None   # removed directly in Discord, not through the bot
            save_sotm_data(data)
            print(f"SOTM {message_id}: poll message was deleted in Discord; poll marked deleted.")


@bot.event
async def on_raw_message_delete(payload: discord.RawMessageDeleteEvent):
    await sotm_mark_message_deleted(payload.message_id)


@bot.event
async def on_raw_bulk_message_delete(payload: discord.RawBulkMessageDeleteEvent):
    for message_id in payload.message_ids:
        await sotm_mark_message_deleted(message_id)


class SotmPollActionView(discord.ui.View):
    """Shown under an active poll's results: Delete Poll."""

    def __init__(self, invoker_id: int, key: str, note: str = None):
        super().__init__(timeout=180)
        self.invoker_id = invoker_id
        self.key = key
        self.note = note

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.invoker_id or not is_giveaway_manager(interaction.user):
            await interaction.response.send_message("This menu is not for you.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Delete Poll", style=discord.ButtonStyle.danger)
    async def delete_poll(self, interaction: discord.Interaction, button: discord.ui.Button):
        poll = load_sotm_data()["polls"].get(self.key)
        if not poll or poll.get("status") == "deleted":
            await interaction.response.edit_message(content="That poll is no longer being tracked.", embed=None, view=None)
            return
        if poll.get("status", "active") != "active":
            await interaction.response.edit_message(
                content="That poll has already ended, so it can no longer be deleted here.", view=None
            )
            return
        name = f"{poll.get('month', '')} {poll.get('year', '')}".strip()
        await interaction.response.edit_message(
            content=(
                f"Delete the **{name}** Staff of the Month poll?\n"
                "It will be removed from the active poll list, its message will be deleted, and it will "
                "stop accepting votes. This cannot be undone."
            ),
            view=SotmDeleteConfirmView(self.invoker_id, self.key, self.note),
        )


class SotmDeleteConfirmView(discord.ui.View):
    def __init__(self, invoker_id: int, key: str, note: str = None):
        super().__init__(timeout=180)
        self.invoker_id = invoker_id
        self.key = key
        self.note = note

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.invoker_id or not is_giveaway_manager(interaction.user):
            await interaction.response.send_message("This menu is not for you.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Confirm Delete", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        poll = load_sotm_data()["polls"].get(self.key) or {}
        name = f"{poll.get('month', '')} {poll.get('year', '')}".strip() or "selected"
        outcome = await sotm_delete_poll(self.key, interaction.user.id)
        if outcome == "not_found":
            text = "That poll is no longer being tracked."
        elif outcome == "not_active":
            text = "That poll has already ended, so it can no longer be deleted here."
        else:
            text = f"The **{name}** Staff of the Month poll has been deleted and no longer accepts votes."
            if outcome == "message_deleted":
                text += "\nThe poll message was also removed from the channel."
            elif outcome == "message_gone":
                text += "\nThe poll message had already been deleted from Discord."
            else:
                text += (
                    "\nI could not delete the poll message from the channel. Check my permissions there. "
                    "Votes on it are now rejected."
                )
        await interaction.response.edit_message(content=text, embed=None, view=None)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(
            content=self.note, view=SotmPollActionView(self.invoker_id, self.key, self.note)
        )


class SotmPollSelect(discord.ui.Select):
    def __init__(self, options: list):
        super().__init__(placeholder="Select a poll...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        # Re-read the saved data so the results reflect the latest votes for the chosen poll.
        poll = load_sotm_data()["polls"].get(self.values[0])
        if not poll or poll.get("status") == "deleted":
            await interaction.response.edit_message(content="That poll is no longer being tracked.", embed=None, view=None)
            return
        await _sotm_send_results(interaction, poll, self.values[0], edit=True)


class SotmPollSelectView(discord.ui.View):
    def __init__(self, invoker_id: int, options: list):
        super().__init__(timeout=180)
        self.invoker_id = invoker_id
        self.add_item(SotmPollSelect(options))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.invoker_id or not is_giveaway_manager(interaction.user):
            await interaction.response.send_message("This menu is not for you.", ephemeral=True)
            return False
        return True


def sotm_poll_options(polls: list) -> list:
    """Dropdown options for (message_id, poll) pairs: active polls first, then ended ones, newest first."""
    ordered = sorted(polls, key=lambda kv: (not sotm_poll_is_open(kv[1]), -int(kv[1].get("created_at", 0))))
    options = []
    for key, poll in ordered[:25]:
        state = "Active" if sotm_poll_is_open(poll) else "Ended"
        label = f"{poll.get('month', 'Unknown')} {poll.get('year', '')}".strip() + f" - {state}"
        created = datetime.fromtimestamp(int(poll.get("created_at", 0)), CENTRAL_TZ).strftime("%b %d, %I:%M %p %Z")
        votes = len(poll.get("votes", {}))
        description = f"Created {created} | {votes} vote{'s' if votes != 1 else ''} | ID {key}"
        options.append(discord.SelectOption(label=label[:100], value=str(key), description=description[:100]))
    return options


@bot.tree.command(name="sotm-results", description="View the current Staff of the Month vote tally.")
async def sotm_results_cmd(interaction: discord.Interaction):
    if interaction.guild is None:
        await interaction.response.send_message("This command can only be used inside a server.", ephemeral=True)
        return
    if not is_giveaway_manager(interaction.user):
        await interaction.response.send_message("You are not authorized to view the results.", ephemeral=True)
        return

    polls = [
        (key, p) for key, p in load_sotm_data()["polls"].items()
        if int(p.get("guild_id", 0)) == interaction.guild.id and p.get("status") != "deleted"
    ]
    if not polls:
        await interaction.response.send_message("No Staff of the Month poll has been created yet.", ephemeral=True)
        return

    # Only one poll exists: show it straight away. Otherwise let the user choose which poll to view.
    if len(polls) == 1:
        await _sotm_send_results(interaction, polls[0][1], polls[0][0])
        return

    await interaction.response.send_message(
        "Select the Staff of the Month poll you want to view.",
        view=SotmPollSelectView(interaction.user.id, sotm_poll_options(polls)),
        ephemeral=True,
    )


# --- /sotm-member: hand the Staff of the Month role to one person ---

SOTM_MEMBER_ROLE_ID = 1543133179286655066   # the Staff of the Month role (only one person holds it at a time)
_sotm_member_lock = asyncio.Lock()          # stops two runs of the command from interleaving


@bot.tree.command(name="sotm-member", description="Give the Staff of the Month role to one member and remove it from everyone else.")
@app_commands.guild_only()
@app_commands.describe(user="The member who is Staff of the Month.")
async def sotm_member_cmd(interaction: discord.Interaction, user: discord.Member):
    guild = interaction.guild
    if guild is None:
        await interaction.response.send_message("This command can only be used inside a server.", ephemeral=True)
        return
    if not is_giveaway_manager(interaction.user):
        await interaction.response.send_message("You are not authorized to use this command.", ephemeral=True)
        return
    if user.bot:
        await interaction.response.send_message("A bot can't be Staff of the Month.", ephemeral=True)
        return

    role = guild.get_role(SOTM_MEMBER_ROLE_ID)
    if role is None:
        await interaction.response.send_message("I can't find the Staff of the Month role in this server.", ephemeral=True)
        return
    if not guild.me.guild_permissions.manage_roles or role >= guild.me.top_role:
        await interaction.response.send_message(
            f"I can't manage {role.mention}. Give me the Manage Roles permission and move my bot role above it "
            "in Server Settings > Roles.",
            ephemeral=True,
            allowed_mentions=discord.AllowedMentions.none(),
        )
        return

    await interaction.response.defer(ephemeral=True)
    no_mentions = discord.AllowedMentions.none()
    reason = f"/sotm-member by {interaction.user} ({interaction.user.id})"

    async with _sotm_member_lock:
        # Make sure the member list is complete so nobody who holds the role is missed.
        if not guild.chunked:
            try:
                await guild.chunk()
            except Exception as exc:
                print(f"SOTM member: guild.chunk() failed: {exc!r}")

        target = guild.get_member(user.id) or user
        previous = [m for m in role.members if m.id != target.id]

        # Give the role to the new person first, so a failure here changes nothing.
        gave = False
        if role not in target.roles:
            try:
                await target.add_roles(role, reason=reason)
                gave = True
            except discord.Forbidden:
                await interaction.followup.send(
                    f"I don't have permission to give {role.mention} to {target.mention}. No roles were changed.",
                    ephemeral=True, allowed_mentions=no_mentions,
                )
                return
            except discord.HTTPException as exc:
                await interaction.followup.send(
                    f"Discord rejected the role change: `{exc}`. No roles were changed.",
                    ephemeral=True, allowed_mentions=no_mentions,
                )
                return

        # Then take it away from everyone else who has it. Only this one role is touched.
        removed, failed = [], []
        for member in previous:
            try:
                await member.remove_roles(role, reason=reason)
                removed.append(member)
            except discord.HTTPException as exc:
                print(f"SOTM member: could not remove the role from {member.id}: {exc!r}")
                failed.append(member)

    lines = [f"{target.mention} is now Staff of the Month and has {role.mention}."
             if gave else f"{target.mention} already had {role.mention}."]
    if removed:
        lines.append("Removed from: " + ", ".join(m.mention for m in removed) + ".")
    elif not previous:
        lines.append("No one else had the role.")
    if failed:
        lines.append(
            "I could not remove the role from: " + ", ".join(m.mention for m in failed)
            + ". Check my permissions and role position, then run the command again."
        )
    await interaction.followup.send("\n".join(lines), ephemeral=True, allowed_mentions=no_mentions)


# --- SAY COMMANDS & MODALS ---

class SayEmbedModal(discord.ui.Modal, title="Post Message (Standard Embed)"):
    embed_title = discord.ui.TextInput(
        label="Title (embed only)",
        placeholder="Enter a title for the embed (leave blank for no title)",
        required=False,
    )
    message = discord.ui.TextInput(
        label="Message",
        style=discord.TextStyle.paragraph,
        placeholder="Type your message here. Supports multiple lines.",
        required=True,
    )
    color_input = discord.ui.TextInput(
        label="Sidebar Color (Hex)",
        placeholder="e.g. 596744 or #CC3333 (Default: 596744)",
        required=False,
    )

    def __init__(self, target_message: discord.Message = None):
        super().__init__()
        self.target_message = target_message
        if target_message and target_message.embeds:
            old = target_message.embeds[0]
            if old.title:
                self.embed_title.default = old.title
            if old.description:
                self.message.default = old.description
            if old.color:
                self.color_input.default = f"#{old.color.value:06x}"

    async def on_submit(self, interaction: discord.Interaction):
        clean_color = self.color_input.value.strip().lstrip("#") if self.color_input.value else "596744"
        try:
            selected_color = int(clean_color, 16)
        except ValueError:
            selected_color = 0x596744

        embed = discord.Embed(
            title=self.embed_title.value.strip() if self.embed_title.value else None,
            description=self.message.value.strip(),
            color=selected_color,
        )
        if self.target_message:
            await self.target_message.edit(content=None, embed=embed)
            await interaction.response.send_message("Message updated successfully.", ephemeral=True)
        else:
            await interaction.channel.send(embed=embed)
            await interaction.response.send_message("Message posted.", ephemeral=True)


class SayEmbedV2Modal(discord.ui.Modal, title="Post Message (Component V2)"):
    header_title = discord.ui.TextInput(label="Header Title", required=False)
    main_text = discord.ui.TextInput(label="Main Body Text", style=discord.TextStyle.paragraph, required=True)
    section_1 = discord.ui.TextInput(label="Inner Section 1", style=discord.TextStyle.paragraph, required=False)
    section_2 = discord.ui.TextInput(label="Inner Section 2", style=discord.TextStyle.paragraph, required=False)

    def __init__(
        self,
        target_message: discord.Message = None,
        existing_title: str = None,
        existing_body: str = None,
        existing_sections: list = None,
    ):
        super().__init__()
        self.target_message = target_message

        if existing_title:
            self.header_title.default = existing_title
        if existing_body:
            self.main_text.default = existing_body

        existing_sections = existing_sections or []
        if len(existing_sections) >= 1:
            self.section_1.default = existing_sections[0]
        if len(existing_sections) >= 2:
            self.section_2.default = existing_sections[1]

    async def on_submit(self, interaction: discord.Interaction):
        sections = []
        if self.section_1.value:
            sections.append(self.section_1.value.strip())
        if self.section_2.value:
            sections.append(self.section_2.value.strip())

        v2_payload = build_v2_payload(
            title=self.header_title.value.strip() if self.header_title.value else None,
            body_text=self.main_text.value.strip() if self.main_text.value else None,
            inner_sections=sections
        )

        if self.target_message:
            # A Components V2 message cannot include a top-level "content" or
            # "embeds" field at all - not even empty ones. Discord rejects
            # the whole request with a 400 if either key is present, so they
            # must be omitted entirely (not just emptied) whenever flags
            # includes IS_COMPONENTS_V2 - Discord clears the old
            # content/embeds itself once that flag is set.
            await interaction.client.http.request(
                discord.http.Route('PATCH', '/channels/{channel_id}/messages/{message_id}', channel_id=interaction.channel_id, message_id=self.target_message.id),
                json={"components": v2_payload, "flags": 32768}
            )
            await interaction.response.send_message("Component V2 message updated successfully.", ephemeral=True)
        else:
            await interaction.client.http.request(
                discord.http.Route('POST', '/channels/{channel_id}/messages', channel_id=interaction.channel_id),
                json={"components": v2_payload, "flags": 32768}
            )
            await interaction.response.send_message("Component V2 message posted.", ephemeral=True)


class SayPlainModal(discord.ui.Modal, title="Post Message (Plain Text)"):
    message = discord.ui.TextInput(
        label="Message",
        style=discord.TextStyle.paragraph,
        required=True,
    )

    def __init__(self, target_message: discord.Message = None):
        super().__init__()
        self.target_message = target_message
        if target_message and target_message.content:
            self.message.default = target_message.content

    async def on_submit(self, interaction: discord.Interaction):
        if self.target_message:
            await self.target_message.edit(content=self.message.value.strip(), embed=None)
            await interaction.response.send_message("Message updated successfully.", ephemeral=True)
        else:
            await interaction.channel.send(content=self.message.value.strip())
            await interaction.response.send_message("Message posted.", ephemeral=True)


@bot.tree.command(name="say", description="Post a message as the bot.")
@app_commands.describe(format_type="Choose the message format")
@app_commands.choices(
    format_type=[
        app_commands.Choice(name="Embed", value="embed"),
        app_commands.Choice(name="V2 Embed", value="embed_v2"),
        app_commands.Choice(name="Plain Text", value="plain"),
    ]
)
async def say_command(interaction: discord.Interaction, format_type: app_commands.Choice[str]):
    if format_type.value == "embed":
        await interaction.response.send_modal(SayEmbedModal())
    elif format_type.value == "embed_v2":
        await interaction.response.send_modal(SayEmbedV2Modal())
    else:
        await interaction.response.send_modal(SayPlainModal())


@app_commands.context_menu(name="Edit Message")
async def edit_say_message_menu(interaction: discord.Interaction, message: discord.Message):
    if message.author != bot.user:
        await interaction.response.send_message("You can only edit messages sent by this bot.", ephemeral=True)
        return

    # Giveaway messages are managed by the giveaway system (and have an attached
    # banner + live entry data), so they must not be rewritten with /say's editor.
    if str(message.id) in load_giveaway_data()["giveaways"]:
        await interaction.response.send_message(
            "Giveaway messages can't be edited here. Use **Reroll Giveaway** for rerolls.",
            ephemeral=True,
        )
        return

    # IS_COMPONENTS_V2 = 1 << 15. Checking the raw flag bit is reliable
    # regardless of whether the installed discord.py version fully parses
    # type 17 (container) components into message.components.
    is_components_v2 = bool(message.flags.value & (1 << 15))

    if is_components_v2:
        try:
            raw_data = await fetch_raw_message(interaction.client, message.channel.id, message.id)
            existing_title, existing_body, existing_sections = parse_v2_container(raw_data.get("components", []))
        except Exception:
            existing_title, existing_body, existing_sections = None, None, []

        await interaction.response.send_modal(
            SayEmbedV2Modal(
                target_message=message,
                existing_title=existing_title,
                existing_body=existing_body,
                existing_sections=existing_sections,
            )
        )
    elif message.embeds:
        embed = message.embeds[0]
        embed_title = embed.title or ""
        if embed_title.startswith("Modlogs for") or embed_title.startswith("Case "):
            await interaction.response.send_message("You can only use Edit Message on standard /say messages.", ephemeral=True)
            return

        await interaction.response.send_modal(SayEmbedModal(target_message=message))
    else:
        await interaction.response.send_modal(SayPlainModal(target_message=message))


# --- CASELOG CONTEXT ACTIONS ---

class EditCaseModal(discord.ui.Modal, title="Edit Caselog"):
    case_num = discord.ui.TextInput(label="Case Number to Edit", placeholder="e.g., 1004", required=True)
    new_reason = discord.ui.TextInput(label="New Reason", style=discord.TextStyle.paragraph, required=True)
    new_evidence = discord.ui.TextInput(label="New Evidence (Optional)", required=False)

    def __init__(self, target_user_id: str, message: discord.Message):
        super().__init__()
        self.target_user_id = target_user_id
        self.message = message

    async def on_submit(self, interaction: discord.Interaction):
        try:
            target_case_id = int(self.case_num.value.strip())
        except ValueError:
            await interaction.response.send_message("Please enter a valid numeric Case ID.", ephemeral=True)
            return

        data = load_data()
        user_cases = data["users"].get(self.target_user_id, [])
        found_case = None

        for case in user_cases:
            if case["case_id"] == target_case_id:
                case["reason"] = self.new_reason.value.strip()
                case["evidence"] = self.new_evidence.value.strip() if self.new_evidence.value else ""
                found_case = case
                break

        if found_case:
            save_data(data)
            unix_time = int(central_now().timestamp())

            sections = [f"**Action:** {found_case['type']}\n**New Reason:** {found_case['reason']}"]
            if found_case["evidence"]:
                sections.append(f"**New Evidence:** {found_case['evidence']}")

            target_user = await interaction.client.fetch_user(int(self.target_user_id))
            await send_v2_dm(
                bot=interaction.client,
                user=target_user,
                title=f"Case #{target_case_id} Updated",
                body_text=f"Your moderation entry in **{interaction.guild.name}** has been updated.\n<t:{unix_time}:F>",
                inner_sections=sections
            )

            log_desc = f"<@{self.target_user_id}> Updated Reason: {found_case['reason']}"
            if found_case["evidence"]:
                log_desc += f"\n\nUpdated Evidence: {found_case['evidence']}"
            log_desc += f"\n\n**Edited At:** <t:{unix_time}:F>"

            await log_to_channel(
                bot=interaction.client,
                guild=interaction.guild,
                channel_id=MOD_LOG_CHANNEL_ID,
                title=f"Case #{target_case_id} | Edited ({found_case['type']})",
                description=log_desc,
                color=0xCC3333,
                footer_text=f"Moderator: @{interaction.user.name} | ID: {self.target_user_id}"
            )

            await interaction.response.send_message(f"Case #{target_case_id} updated successfully.", ephemeral=True)
        else:
            await interaction.response.send_message(f"Case #{target_case_id} was not found for this user.", ephemeral=True)


class DeleteCaseModal(discord.ui.Modal, title="Delete Caselog"):
    case_num = discord.ui.TextInput(label="Case Number to Delete", placeholder="e.g., 1004", required=True)
    delete_reason = discord.ui.TextInput(label="Reason for Deletion", style=discord.TextStyle.paragraph, required=True)

    def __init__(self, target_user_id: str):
        super().__init__()
        self.target_user_id = target_user_id

    async def on_submit(self, interaction: discord.Interaction):
        try:
            target_case_id = int(self.case_num.value.strip())
        except ValueError:
            await interaction.response.send_message("Please enter a valid numeric Case ID.", ephemeral=True)
            return

        reason_text = self.delete_reason.value.strip()
        data = load_data()

        if self.target_user_id in data["users"]:
            initial_count = len(data["users"][self.target_user_id])
            deleted_case_type = None

            for c in data["users"][self.target_user_id]:
                if c["case_id"] == target_case_id:
                    deleted_case_type = c.get("type", "Moderation Action")
                    break

            data["users"][self.target_user_id] = [c for c in data["users"][self.target_user_id] if c["case_id"] != target_case_id]

            if len(data["users"][self.target_user_id]) < initial_count:
                save_data(data)
                unix_time = int(central_now().timestamp())

                role_name = PUNISHMENT_ROLES.get(deleted_case_type)
                if interaction.guild and role_name:
                    member = interaction.guild.get_member(int(self.target_user_id))
                    if member:
                        role = discord.utils.get(interaction.guild.roles, name=role_name)
                        if role and role in member.roles:
                            try:
                                await member.remove_roles(role)
                            except discord.Forbidden:
                                pass

                target_user = await interaction.client.fetch_user(int(self.target_user_id))
                await send_v2_dm(
                    bot=interaction.client,
                    user=target_user,
                    title=f"Case #{target_case_id} Removed",
                    body_text=f"Your moderation entry in **{interaction.guild.name}** has been removed.\n<t:{unix_time}:F>",
                    inner_sections=[f"**Action Removed:** {deleted_case_type}\n**Reason:** {reason_text}"]
                )

                await log_to_channel(
                    bot=interaction.client,
                    guild=interaction.guild,
                    channel_id=MOD_LOG_CHANNEL_ID,
                    title=f"Case #{target_case_id} | Deleted",
                    description=f"<@{self.target_user_id}> Action removed: {deleted_case_type}\n\n**Deletion Reason:** {reason_text}\n\n**Deleted At:** <t:{unix_time}:F>",
                    color=0xCC3333,
                    footer_text=f"Moderator: @{interaction.user.name} | ID: {self.target_user_id}"
                )

                await interaction.response.send_message(f"Case #{target_case_id} deleted successfully.", ephemeral=True)
                return

        await interaction.response.send_message(f"Case #{target_case_id} was not found for this user.", ephemeral=True)


@app_commands.context_menu(name="Edit Caselog")
async def edit_caselog_menu(interaction: discord.Interaction, message: discord.Message):
    # No code-level staff/permission gate here; Discord command permissions control access.
    if not message.embeds:
        await interaction.response.send_message("You can only edit caselog messages.", ephemeral=True)
        return

    embed = message.embeds[0]
    if not embed.title or not embed.title.startswith("Modlogs for"):
        await interaction.response.send_message("You can only edit caselog messages.", ephemeral=True)
        return

    user_id = embed.description.split("\n")[0].replace("<@", "").replace(">", "").strip()
    await interaction.response.send_modal(EditCaseModal(target_user_id=user_id, message=message))


@app_commands.context_menu(name="Delete Caselog")
async def delete_caselog_menu(interaction: discord.Interaction, message: discord.Message):
    # No code-level staff/permission gate here; Discord command permissions control access.
    if not message.embeds:
        await interaction.response.send_message("You can only delete caselog messages.", ephemeral=True)
        return

    embed = message.embeds[0]
    if not embed.title or not embed.title.startswith("Modlogs for"):
        await interaction.response.send_message("You can only delete caselog messages.", ephemeral=True)
        return

    user_id = embed.description.split("\n")[0].replace("<@", "").replace(">", "").strip()
    await interaction.response.send_modal(DeleteCaseModal(target_user_id=user_id))

import time
import aiohttp

with open("token.txt") as f:
    TOKEN = f.read().strip()

def run_forever():
    delay = 5
    max_delay = 300
    while True:
        try:
            bot.run(TOKEN)
            break
        except (aiohttp.ClientConnectorError, ConnectionRefusedError, OSError) as e:
            print(f"[startup] Could not reach Discord ({e}). Retrying in {delay}s...")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)
        except Exception:
            raise


@bot.command(name="copyperms")
@role_or_above_check(SERVER_STAFF_ROLE_ID)
async def copyperms(ctx, source_id: str = None, *, target_ids: str = ""):
    """Copy this channel's permission overwrites using numeric role IDs only; never ping roles."""
    channel = ctx.channel
    if ctx.guild is None or not isinstance(channel, discord.abc.GuildChannel) or not hasattr(channel, "set_permissions"):
        await ctx.send("This command can only be used in a server channel that supports permission overwrites.", delete_after=10)
        return

    # IDs only: role mentions are deliberately not accepted as input.
    raw_ids = ([source_id] if source_id else []) + target_ids.split()
    if len(raw_ids) < 2:
        await ctx.send("Usage: `-copyperms SOURCE_ROLE_ID TARGET_ROLE_ID [TARGET_ROLE_ID ...]`", delete_after=12)
        return
    if any(not item.isdigit() for item in raw_ids):
        await ctx.send("Use numeric role IDs only. Do not mention roles.", delete_after=10, allowed_mentions=discord.AllowedMentions.none())
        return

    source = ctx.guild.get_role(int(raw_ids[0]))
    if source is None:
        await ctx.send(f"Source role ID `{raw_ids[0]}` was not found in this server.", delete_after=10)
        return
    unique_targets = []
    seen_ids = set()
    for raw_id in raw_ids[1:]:
        role = ctx.guild.get_role(int(raw_id))
        if role is None:
            await ctx.send(f"Target role ID `{raw_id}` was not found in this server.", delete_after=10)
            return
        if role.is_default():
            await ctx.send("The @everyone role cannot be used as a target role.", delete_after=10, allowed_mentions=discord.AllowedMentions.none())
            return
        if role.id != source.id and role.id not in seen_ids:
            unique_targets.append(role)
            seen_ids.add(role.id)
    if not unique_targets:
        await ctx.send("Please provide at least one valid target role ID other than the source role ID.", delete_after=10)
        return

    me = ctx.guild.me
    if me is None or not me.guild_permissions.manage_roles:
        await ctx.send("I need the Manage Roles permission to update channel permission overwrites.", delete_after=12)
        return

    source_overwrite = channel.overwrites_for(source)
    updated, failed = [], []
    for role in unique_targets:
        try:
            await channel.set_permissions(role, overwrite=source_overwrite,
                reason=f"Channel permissions copied from role ID {source.id} by user ID {ctx.author.id}")
            updated.append(role)
        except (discord.Forbidden, discord.HTTPException):
            failed.append(role)

    lines = [f"**Channel:** {channel.name} (`{channel.id}`)", f"**Source role:** {source.name} (`{source.id}`)"]
    if updated:
        lines.append("**Updated target roles:** " + ", ".join(f"{r.name} (`{r.id}`)" for r in updated))
    if failed:
        lines.append("**Could not update:** " + ", ".join(f"{r.name} (`{r.id}`)" for r in failed))
    lines.append("Only this channel's permission overwrites were changed. No roles were pinged.")
    await ctx.send("\n".join(lines), allowed_mentions=discord.AllowedMentions.none())


# Disable the old Startup 1 and Startup 2 prefix commands for everyone.
# The separate slash commands for Early Access remain unchanged.
bot.remove_command("start-up1")
bot.remove_command("start-up2")

@bot.command(name="sitetest")
@commands.has_permissions(administrator=True)
async def sitetest(ctx):
    """Check every link in the transcript-website chain and report in Discord."""
    if not site_publisher:
        if not _SITE_CRYPTO_OK:
            await ctx.send("\u274c The 'cryptography' package is not installed. Add a line `cryptography` to requirements.txt and restart.")
        elif os.path.exists(SITE_CONFIG_FILE):
            await ctx.send("\u274c transcript_site.json was found but is invalid. Check for a missing comma or quote, and that it has token, repo and password.")
        else:
            await ctx.send(f"\u274c transcript_site.json not found. Create it exactly here: `{SITE_CONFIG_FILE}`")
        return
    msg = await ctx.send("Testing the transcript site\u2026")
    await msg.edit(content=await site_publisher.diagnose())


if __name__ == "__main__":
    run_forever()
