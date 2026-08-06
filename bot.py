#!/usr/bin/env python3
"""
Sentry — a lightweight Discord image moderation bot backed by Claude vision.

Flow:
  user posts image -> bot downloads and downscales it -> Claude classifies ->
  clean images are left untouched -> flagged images are deleted, the author
  loses attach/embed permissions, and a case opens in the review channel.

Nothing is reposted, so clean messages keep their real author, replies,
reactions and edit history. /post provides a zero-exposure path when the
brief visibility window during the check is unacceptable.

Single file, no database. State lives in one JSON file.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import logging.handlers
import os
import re
import sqlite3
import time
from collections import OrderedDict
from html import escape as _esc
from pathlib import Path
from typing import Any

import aiohttp
import anthropic
import discord
from aiohttp import web
from anthropic import AsyncAnthropic
from discord import app_commands

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

try:
    from PIL import Image

    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DISCORD_TOKEN = os.environ["DISCORD_TOKEN"]
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]

MODEL = os.getenv("SENTRY_MODEL", "claude-haiku-4-5-20251001")
ASK_MODEL = os.getenv("SENTRY_ASK_MODEL", MODEL)  # model for the /sentry ask helper
STATE_PATH = Path(os.getenv("SENTRY_STATE", "sentry_state.json"))
RESTRICTED_ROLE_NAME = "Media Restricted"

# Long edge we downscale to before sending to Claude. 768px is plenty for
# nudity/gore classification and costs ~800 input tokens per image.
MAX_EDGE = int(os.getenv("SENTRY_MAX_EDGE", "768"))

# Hard ceiling from the API: 5 MB per base64 image, 8000x8000 px.
API_IMAGE_BYTE_LIMIT = 5 * 1024 * 1024

# Minimum Claude confidence (0-1) needed to quarantine a flagged image. A failed
# check (API error, undecodable/oversize file) NEVER takes action — the message is
# left up — so an outage or a weird file can't mass-delete content.
CONFIDENCE_LEVELS = {"low": 0.60, "medium": 0.75, "high": 0.90}
DEFAULT_MIN_CONFIDENCE = CONFIDENCE_LEVELS["medium"]

# Every moderation category, in display order. Single source of truth shared by the
# /sentry category command and the admin dashboard.
CATEGORIES = (
    "sexual_nudity",
    "gore",
    "hate_symbol",
    "violence_threat",
    "harassment_doxxing",
    "self_harm",
    "drugs",
    "scam_spam",
)
SENSITIVITY_LEVELS = ("relaxed", "standard", "strict")

# Feature gating (monetization). A non-allowlisted ("free") guild watches every
# category but is locked to watch-only mode (reports, removes nothing) and
# is capped per day; allowlisting a guild ("paying") lets it actually enforce. The
# allowlist is the bot owner's, via SENTRY_ALLOWLIST (comma ids) or /sentry allowlist.
FREE_SCAN_LIMIT = int(os.getenv("SENTRY_FREE_SCAN_LIMIT", "50"))  # free scans per UTC day
DEFAULT_DRY_RUN = True  # watch-only until a (premium) guild opts into enforcing
ALLOWLIST_ENV = {
    s.strip() for s in os.getenv("SENTRY_ALLOWLIST", "").split(",") if s.strip()
}
OWNER_ID = int(os.getenv("SENTRY_OWNER_ID", "0"))  # 0 => resolved from the app owner

# Max simultaneous Claude calls. Higher = shorter visibility window under a raid, but
# bounded by your Anthropic rate-limit tier (429s self-throttle via retry-after below)
# and the host's RAM/CPU. Raise it on a bigger box.
MAX_CONCURRENT_CHECKS = int(os.getenv("SENTRY_CONCURRENCY", "8"))
VERDICT_CACHE_SIZE = 512

# Perceptual re-block: a newly posted image within this Hamming distance (of 64) of a
# previously blocked image is re-blocked from cache without calling Claude — catches
# re-compressed/resized/lightly-edited reposts of banned content, not just exact bytes.
# Lower = stricter (fewer false matches). Set < 0 to disable (exact-hash only).
PHASH_DISTANCE = int(os.getenv("SENTRY_PHASH_DISTANCE", "5"))

SUPPORTED_MIME = {"image/jpeg", "image/png", "image/gif", "image/webp"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger("sentry")


# Persistent, rotating audit log (one JSON object per line). It lives next to the
# state file — outside the git tree — so a full record of every removal, check
# failure, and moderator action survives the bot being kicked from a server,
# restarts, and redeploys. Override the path with SENTRY_AUDIT_LOG.
AUDIT_LOG_PATH = Path(
    os.getenv("SENTRY_AUDIT_LOG", str(STATE_PATH.parent / "audit.jsonl"))
)
audit_log = logging.getLogger("sentry.audit")
audit_log.setLevel(logging.INFO)
audit_log.propagate = False
try:
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _audit_handler = logging.handlers.RotatingFileHandler(
        AUDIT_LOG_PATH, maxBytes=5_000_000, backupCount=5, encoding="utf-8"
    )
    _audit_handler.setFormatter(logging.Formatter("%(message)s"))
    audit_log.addHandler(_audit_handler)
except Exception:
    log.exception("could not open audit log at %s", AUDIT_LOG_PATH)


def audit(event: str, **fields: Any) -> None:
    """Append one JSON line to the persistent audit log. Never raises."""
    try:
        record = {"ts": discord.utils.utcnow().isoformat(), "event": event, **fields}
        audit_log.info(json.dumps(record, default=str))
    except Exception:
        log.exception("audit logging failed")


# Optional local archive of blocked image bytes, for reviewing false positives. OFF
# unless SENTRY_ARCHIVE_BLOCKED is a positive number of retention days. Files are named
# by sha256 (matching the audit log) and live next to the state file outside the git tree.
ARCHIVE_BLOCKED_DAYS = int(os.getenv("SENTRY_ARCHIVE_BLOCKED", "0"))
ARCHIVE_DIR = STATE_PATH.parent / "blocked"


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

# Per-guild defaults. Mutable defaults are factories (list/dict) so every guild
# gets its own instance. Backfilled into existing guilds on access, so a guild
# stored before a field was added still picks up that field's default.
_GUILD_DEFAULTS: dict[str, Any] = {
    "review_channel": None,
    "restricted_role": None,
    "enabled": True,
    "sensitivity": "standard",  # relaxed | standard | strict
    "exempt_channels": list,
    "approved_hashes": list,  # sha256s a mod approved; never re-flagged
    "blocked_hashes": dict,  # sha256 -> verdict; reposts skip Claude
    "approved_posts": dict,  # sha256 -> [[channel_id, message_id]] reposts
    "min_confidence": DEFAULT_MIN_CONFIDENCE,  # quarantine threshold
    "disabled_categories": list,  # categories a mod turned off
    "dry_run": DEFAULT_DRY_RUN,  # watch-only until (premium) enforce opt-in
    "scan_day": None,  # UTC date of the current daily scan window
    "scan_count": 0,  # scans used in that window
    "quota_notified": False,  # posted the "quota reached" notice yet
    "alert_role": None,  # role pinged on every removal
    "allowances": list,  # community-specific exceptions injected into the prompt
    "exempt_reviewers": True,  # skip anyone who can see the review channel (staff)
}


STATE_FLUSH_DELAY = float(os.getenv("SENTRY_FLUSH_DELAY", "2.0"))  # debounce seconds


class State:
    """Per-guild config store, backed by SQLite (a key→JSON row per guild plus the
    reserved ``__allowlist__`` key). The whole store is mirrored in memory and
    mutated in place exactly as before; ``save()`` no longer rewrites everything
    synchronously — it marks the store dirty and schedules a **debounced** flush
    that writes only the keys whose value actually changed. This turns the old
    per-scan full-file rewrite into at most one small, changed-rows-only write
    every ``STATE_FLUSH_DELAY`` seconds, which is what lets it scale to many
    servers. The legacy JSON file is migrated in once, then left as a backup."""

    def __init__(self, path: Path):
        self.path = path  # legacy JSON path — used once for migration, then a backup
        self.db_path = path.with_suffix(".db")
        self.data: dict[str, dict[str, Any]] = {}
        self._written: dict[str, int] = {}  # key -> hash of last-persisted JSON
        self._dirty = False
        self._flush_handle: asyncio.TimerHandle | None = None

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.db_path)
        self._db.execute("PRAGMA journal_mode=WAL")   # concurrent reads, cheap writes
        self._db.execute("PRAGMA synchronous=NORMAL")  # durable enough, far faster
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._db.commit()
        self._load()
        if not self.data and path.exists():
            self._migrate_json()

    def _load(self) -> None:
        for key, blob in self._db.execute("SELECT key, value FROM kv"):
            try:
                self.data[key] = json.loads(blob)
                self._written[key] = hash(blob)
            except ValueError:
                log.warning("skipping unreadable state row for %s", key)

    def _migrate_json(self) -> None:
        try:
            data = json.loads(self.path.read_text())
        except Exception:
            log.exception("legacy state file unreadable; starting fresh")
            return
        if not isinstance(data, dict):
            return
        self.data = data
        self._dirty = True
        self._flush()  # persist everything into the DB now (no event loop needed)
        log.info(
            "migrated %d keys from %s into %s (JSON kept as backup)",
            len(data), self.path, self.db_path,
        )

    def guild(self, guild_id: int) -> dict[str, Any]:
        cfg = self.data.setdefault(str(guild_id), {})
        # Backfill missing keys so guilds created before a field existed still
        # get its default — setdefault on the whole dict only helps new guilds.
        for key, default in _GUILD_DEFAULTS.items():
            if key not in cfg:
                cfg[key] = default() if callable(default) else default
        return cfg

    # --- premium allowlist (bot-owner controlled, stored under a reserved key) ---

    def is_allowed(self, guild_id: int) -> bool:
        s = str(guild_id)
        return s in ALLOWLIST_ENV or s in self.data.get("__allowlist__", [])

    def is_env_allowed(self, guild_id: int) -> bool:
        return str(guild_id) in ALLOWLIST_ENV

    def is_state_allowed(self, guild_id: int) -> bool:
        return str(guild_id) in self.data.get("__allowlist__", [])

    def set_allowed(self, guild_id: int, on: bool) -> None:
        lst = self.data.setdefault("__allowlist__", [])
        s = str(guild_id)
        if on and s not in lst:
            lst.append(s)
        elif not on and s in lst:
            lst.remove(s)
        self.save()

    def allowlist(self) -> list[str]:
        return list(self.data.get("__allowlist__", [])) + sorted(ALLOWLIST_ENV)

    # --- bot-global metadata (command sync bookkeeping, etc.) ---

    def meta(self) -> dict[str, Any]:
        return self.data.setdefault("__meta__", {})

    def save(self) -> None:
        """Mark the store dirty and schedule a debounced flush. Callers keep using
        this exactly as before — it just no longer blocks on a full rewrite."""
        self._dirty = True
        if self._flush_handle is not None:
            return  # a flush is already scheduled
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._flush()  # no loop yet (startup/migration/tests) — write now
            return
        self._flush_handle = loop.call_later(STATE_FLUSH_DELAY, self._on_timer)

    def _on_timer(self) -> None:
        self._flush_handle = None
        self._flush()

    def _flush(self) -> None:
        """Write only the keys whose serialized value changed since the last flush."""
        if not self._dirty:
            return
        self._dirty = False
        rows = []
        for key, value in self.data.items():
            blob = json.dumps(value)
            if self._written.get(key) != hash(blob):
                rows.append((key, blob))
        if not rows:
            return
        try:
            with self._db:
                self._db.executemany(
                    "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", rows
                )
        except sqlite3.Error:
            log.exception("state flush failed; will retry on next save")
            self._dirty = True
            return
        for key, blob in rows:
            self._written[key] = hash(blob)

    def flush(self) -> None:
        """Force an immediate synchronous write. Call on shutdown so a pending
        debounced flush isn't lost."""
        if self._flush_handle is not None:
            self._flush_handle.cancel()
            self._flush_handle = None
        self._flush()

    def close(self) -> None:
        self.flush()
        self._db.close()


state = State(STATE_PATH)


# --------------------------------------------------------------------------
# Classifier
# --------------------------------------------------------------------------

claude = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
check_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
verdict_cache: "OrderedDict[str, dict]" = OrderedDict()

SYSTEM_PROMPT = """You are an image safety classifier for a general-audience \
Discord server. You receive one image and return a single JSON object. You never \
describe the image in detail, never narrate its contents, and never output anything \
except JSON.

Your job is to flag images that do not belong on a general-audience community \
server. Categories:
- "sexual_nudity": exposed genitals, anus, or female nipples; sexual acts; \
sexually explicit posing or content clearly intended to arouse.
- "gore": graphic injury, mutilation, visible internal anatomy, significant \
blood from real trauma, corpses, animal cruelty, real-world death.
- "hate_symbol": Nazi, SS, KKK, or other recognized white-supremacist, extremist, \
or terrorist symbols, flags, or salutes; hateful slurs rendered in the image; \
dehumanizing hateful caricatures of a protected group.
- "violence_threat": glorification or promotion of terrorism or mass violence; a \
credible real-world threat; a weapon brandished to menace a specific person.
- "harassment_doxxing": an image posted to expose a private individual's personal \
information (home address, phone number, government ID, financial details) or to \
demean and harass a specific person.
- "self_harm": depiction, instruction, or promotion of suicide or self-harm.
- "drugs": use, sale, or promotion of hard or illegal drugs.
- "scam_spam": phishing, fraudulent giveaways or investment/crypto scams, QR codes \
or links presented to defraud, or mass unsolicited advertising.
- "clean": everything else.

Calibration — these are CLEAN:
- Swimwear, underwear, shirtless people, athletic wear, non-explicit figure \
studies, cleavage, and cosplay.
- Stylized cartoon violence, video game screenshots, horror movie makeup, film \
stills, memes with fake blood, and medical or educational diagrams.
- Historical and educational material: WWII documentary photos, museum pieces, \
news reporting, and anti-hate imagery such as a crossed-out swastika.
- The Hindu, Buddhist, or Jain swastika and similar religious symbols in a genuine \
cultural or religious context — not every swastika is a hate symbol.
- Lawful weapons in ordinary context (hunting, sport, collecting, game \
screenshots), and alcohol or tobacco in ordinary social use.
- Jokes, satire, and edgy humor that do not actually promote harm.

Rules:
- Real photographic injury, real accident and war footage, and surgical footage \
are GORE even when the intent is educational.
- Judge what is depicted. For hate_symbol, scam_spam, harassment_doxxing and \
self_harm, any text and context shown in the image are part of what is depicted \
and should be weighed.
- When something is borderline and could plausibly be innocuous, prefer "clean". A \
wrong block deletes a real user's message.
- Set "verdict" to "block" for any category other than "clean"; use "allow" only \
for "clean".

Sensitivity level "{sensitivity}":
- relaxed: flag only unambiguous, explicit cases.
- standard: flag when a reasonable moderator on a general-audience server would.
- strict: also flag suggestive-but-not-explicit sexual content, moderate blood, \
and borderline cases in the other categories.
{allowances}
Respond with exactly this JSON shape and nothing else:
{{"verdict": "allow" | "block", "category": "clean" | "sexual_nudity" | "gore" | "hate_symbol" | "violence_threat" | "harassment_doxxing" | "self_harm" | "drugs" | "scam_spam", "confidence": 0.0-1.0, "reason": "<max 12 words, non-graphic>"}}"""


ALLOWANCE_MAX = 20  # cap how many custom rules go into the prompt


def _allowances_text(cfg: dict) -> str:
    """Render a guild's custom allowances into a prompt block (empty if none). These
    let a server carve out community-specific exceptions — e.g. a predominantly Black
    community permitting reclaimed in-group use of a slur that would otherwise be
    flagged as hate_symbol."""
    rules = [str(r).strip() for r in cfg.get("allowances", []) if str(r).strip()]
    if not rules:
        return ""
    lines = "\n".join(f"- {r}" for r in rules[:ALLOWANCE_MAX])
    return (
        "\nServer-specific allowances — this community has explicitly permitted the "
        "following, so do NOT treat any listed item as a reason to flag. Return "
        '"allow"/"clean" only if EVERY reason you would otherwise flag the image is '
        "covered by this list; if even one reason is not listed here, classify "
        "normally. (For example, an allowance for a reclaimed slur does not by itself "
        "excuse separate hateful imagery such as a blackface caricature.) Allowances:\n"
        f"{lines}\n"
    )


def _cache_get(key: str) -> dict | None:
    if key in verdict_cache:
        verdict_cache.move_to_end(key)
        return verdict_cache[key]
    return None


def _cache_put(key: str, value: dict) -> None:
    verdict_cache[key] = value
    verdict_cache.move_to_end(key)
    while len(verdict_cache) > VERDICT_CACHE_SIZE:
        verdict_cache.popitem(last=False)


GIF_SAMPLE_FRAMES = max(1, int(os.getenv("SENTRY_GIF_FRAMES", "4")))


def _sniff_mime(raw: bytes) -> str | None:
    """The real image media type from magic bytes — the declared mime is unreliable
    (embeds/stickers are guessed as png), and a wrong media_type makes the API 400."""
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if raw[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "image/webp"
    return None


def _extract_frames(raw: bytes, mime: str) -> list[tuple[str, str]]:
    """Return up to GIF_SAMPLE_FRAMES (base64_jpeg, media_type) sampled evenly across
    an image. Static images yield one frame; animated GIF/WebP/APNG yield several so a
    bad frame later in the loop isn't missed. Empty list if it can't be decoded."""
    if HAS_PIL:
        try:
            with Image.open(io.BytesIO(raw)) as img:
                n = getattr(img, "n_frames", 1)
                if n <= 1:
                    indices = [0]
                else:
                    k = min(GIF_SAMPLE_FRAMES, n)
                    indices = sorted({round(i * (n - 1) / (k - 1)) for i in range(k)})
                out = []
                for idx in indices:
                    img.seek(idx)
                    frame = img.convert("RGB")
                    frame.thumbnail((MAX_EDGE, MAX_EDGE), Image.LANCZOS)
                    buf = io.BytesIO()
                    frame.save(buf, format="JPEG", quality=80, optimize=True)
                    out.append(
                        (base64.standard_b64encode(buf.getvalue()).decode(), "image/jpeg")
                    )
                return out
        except Exception:
            log.warning(
                "pillow failed to decode image; falling back to a single-frame scan",
                exc_info=True,
            )

    # PIL absent or it failed on this image: send the raw bytes as one frame, labeled
    # by their ACTUAL sniffed format so a wrong media_type can't 400 the API.
    media = _sniff_mime(raw) or (mime if mime in SUPPORTED_MIME else None)
    if media in SUPPORTED_MIME and len(raw) <= API_IMAGE_BYTE_LIMIT * 0.7:
        return [(base64.standard_b64encode(raw).decode(), media)]
    return []


_DHASH_SIZE = 8  # -> a 64-bit difference hash


def _dhash(raw: bytes) -> int | None:
    """64-bit perceptual difference-hash: visually similar images have a small Hamming
    distance even when their bytes differ. Pure Pillow; None if undecodable."""
    if not HAS_PIL:
        return None
    try:
        with Image.open(io.BytesIO(raw)) as img:
            img.draft("L", (_DHASH_SIZE * 4, _DHASH_SIZE * 4))  # fast JPEG downscale hint
            small = img.convert("L").resize((_DHASH_SIZE + 1, _DHASH_SIZE), Image.LANCZOS)
        px = small.load()
        bits = 0
        for y in range(_DHASH_SIZE):
            for x in range(_DHASH_SIZE):
                bits = (bits << 1) | (1 if px[x, y] > px[x + 1, y] else 0)
        # 0 / all-ones are degenerate (flat or perfectly-graded images); treat as "no
        # useful hash" so unrelated low-detail images don't all collide.
        return bits if bits not in (0, (1 << (_DHASH_SIZE * _DHASH_SIZE)) - 1) else None
    except Exception:
        return None


def _nearest_blocked(phash: int, blocked: dict, max_distance: int) -> dict | None:
    """First blocked entry whose stored perceptual hash is within max_distance of
    phash, or None. Entries without a stored phash (older blocks) are skipped."""
    for entry in blocked.values():
        stored = entry.get("phash")
        if stored is not None and (phash ^ stored).bit_count() <= max_distance:
            return entry
    return None


_RETRYABLE_STATUS = {429, 500, 502, 503, 504, 529}


async def _classify_one(
    data: str, media_type: str, sensitivity: str, allowances: str = ""
) -> dict:
    """One Claude vision call on one prepared frame, retrying transient failures with
    backoff. Never raises; fails open (verdict=allow, error=True) once it gives up."""
    for attempt in range(3):
        delay = 2**attempt  # default backoff: 1s, 2s
        try:
            async with check_semaphore:
                resp = await claude.messages.create(
                    model=MODEL,
                    max_tokens=150,
                    system=SYSTEM_PROMPT.format(
                        sensitivity=sensitivity, allowances=allowances
                    ),
                    messages=[
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "image",
                                    "source": {
                                        "type": "base64",
                                        "media_type": media_type,
                                        "data": data,
                                    },
                                },
                                {"type": "text", "text": "Classify this image."},
                            ],
                        },
                        # Prefill forces bare JSON, no preamble.
                        {"role": "assistant", "content": "{"},
                    ],
                )
            text = "{" + "".join(
                b.text for b in resp.content if getattr(b, "type", "") == "text"
            )
            verdict = json.loads(text[: text.rindex("}") + 1])
            verdict.setdefault("verdict", "block")
            verdict.setdefault("category", "unknown")
            verdict.setdefault("reason", "")
            # Claude occasionally quotes the number; coerce so downstream compares/formats
            # can't blow up on a str.
            try:
                verdict["confidence"] = float(verdict.get("confidence", 0.0))
            except (TypeError, ValueError):
                verdict["confidence"] = 0.0
            verdict["error"] = False
            return verdict
        except anthropic.APIConnectionError:  # network errors and timeouts
            retryable = True
        except anthropic.APIStatusError as e:
            retryable = e.status_code in _RETRYABLE_STATUS
            if retryable and e.status_code == 429:
                # Rate-limited: wait the server-suggested time (capped so a single scan
                # can't hang) instead of a blind backoff — matters at high concurrency.
                try:
                    retry_after = float(e.response.headers.get("retry-after", 0))
                    if retry_after > 0:
                        delay = min(retry_after, 10.0)
                except (TypeError, ValueError, AttributeError):
                    pass
            elif not retryable:
                log.warning("classification rejected (%s): %s", e.status_code, e)
        except Exception:
            log.exception("classification failed")
            retryable = False
        if not retryable or attempt == 2:
            break
        await asyncio.sleep(delay)

    return {
        "verdict": "allow",  # fail open: a failed check never takes action
        "category": "check_failed",
        "confidence": 0.0,
        "reason": "moderation check errored",
        "error": True,
    }


async def classify(
    raw: bytes, mime: str, sensitivity: str, allowances: str = ""
) -> dict:
    """Return a verdict dict for an image. Never raises. For an animation, frames are
    checked in order and the first blocked frame condemns the whole thing."""
    digest = hashlib.sha256(raw).hexdigest()
    # Allowances change the verdict, so they must be part of the cache key — otherwise
    # one guild's exception would leak to another via the shared process cache.
    allow_key = hashlib.sha256(allowances.encode()).hexdigest()[:12] if allowances else ""
    cache_key = f"{digest}:{sensitivity}:{allow_key}"
    if cached := _cache_get(cache_key):
        return cached

    # Pillow decode/resize/encode is CPU-heavy and synchronous; run it off the event
    # loop so it can't stall the gateway or slash-command handling on a small VM.
    frames = await asyncio.to_thread(_extract_frames, raw, mime)
    if not frames:
        # Fail open and don't cache: an undecodable/oversize file takes no action.
        return {
            "verdict": "allow",
            "category": "unscannable",
            "confidence": 0.0,
            "reason": "file type or size not scannable",
            "error": True,
        }

    verdict = None
    for data, media_type in frames:
        verdict = await _classify_one(data, media_type, sensitivity, allowances)
        if verdict.get("verdict") == "block":
            break  # one bad frame is enough

    # Never cache a transient failure, or a brief outage would keep returning it for
    # the rest of the session.
    if not verdict.get("error"):
        _cache_put(cache_key, verdict)
    return verdict


# --------------------------------------------------------------------------
# Bot
# --------------------------------------------------------------------------


class Sentry(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True  # required to see attachments
        intents.guilds = True
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.http_session: aiohttp.ClientSession | None = None

    async def setup_hook(self):
        self.http_session = aiohttp.ClientSession()
        self.add_view(ReviewView())  # persistent buttons survive restarts
        self.add_view(UndoApprovalView())
        self.add_view(UpheldView())
        self.add_view(RestoredView())
        global OWNER_ID
        if not OWNER_ID:
            try:
                info = await self.application_info()
                OWNER_ID = info.owner.id
                log.info("resolved bot owner: %s", OWNER_ID)
            except Exception:
                log.exception("could not resolve application owner")
        await start_admin_dashboard()
        # Commands are synced globally in on_ready, only when they've changed.

    async def close(self):
        state.flush()  # persist any debounced writes before we go down
        await stop_admin_dashboard()
        if self.http_session:
            await self.http_session.close()
        await super().close()

bot = Sentry()


# --------------------------------------------------------------------------
# Restriction handling
# --------------------------------------------------------------------------


async def get_restricted_role(guild: discord.Guild) -> discord.Role:
    """Fetch or build the role that denies attaching files and embedding links.

    Role-level denies do not work at the guild level in Discord (permissions are
    additive), so the deny has to be applied as a channel overwrite everywhere.
    """
    cfg = state.guild(guild.id)
    if cfg["restricted_role"]:
        role = guild.get_role(cfg["restricted_role"])
        if role:
            return role

    role = discord.utils.get(guild.roles, name=RESTRICTED_ROLE_NAME)
    if role is None:
        role = await guild.create_role(
            name=RESTRICTED_ROLE_NAME,
            colour=discord.Colour.dark_grey(),
            reason="Sentry: media restriction role",
        )

    for channel in guild.channels:
        if isinstance(channel, discord.CategoryChannel) or channel.permissions_for(
            guild.me
        ).manage_roles:
            try:
                await channel.set_permissions(
                    role,
                    attach_files=False,
                    embed_links=False,
                    reason="Sentry: media restriction",
                )
            except discord.Forbidden:
                continue

    cfg["restricted_role"] = role.id
    state.save()
    return role


async def restrict(member: discord.Member, reason: str) -> bool:
    try:
        role = await get_restricted_role(member.guild)
        await member.add_roles(role, reason=f"Sentry: {reason}")
        return True
    except discord.Forbidden:
        log.warning("missing permissions to restrict %s", member)
        return False


async def unrestrict(member: discord.Member, reason: str) -> bool:
    cfg = state.guild(member.guild.id)
    role = member.guild.get_role(cfg["restricted_role"]) if cfg["restricted_role"] else None
    if role is None:
        role = discord.utils.get(member.guild.roles, name=RESTRICTED_ROLE_NAME)
    if role is None or role not in member.roles:
        return False
    try:
        await member.remove_roles(role, reason=f"Sentry: {reason}")
        return True
    except discord.Forbidden:
        return False


# --------------------------------------------------------------------------
# Review UI
# --------------------------------------------------------------------------


class ReviewView(discord.ui.View):
    """Persistent buttons. All context is encoded in the custom_id."""

    def __init__(self):
        super().__init__(timeout=None)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not interaction.user.guild_permissions.manage_messages:
            await interaction.response.send_message(
                "You need Manage Messages to action this case.", ephemeral=True
            )
            return False
        return True

    @discord.ui.button(
        label="Restore access",
        style=discord.ButtonStyle.success,
        custom_id="sentry:restore",
    )
    async def restore(self, interaction: discord.Interaction, button: discord.ui.Button):
        await _flip_restriction(interaction, restore=True, first_time=True)

    @discord.ui.button(
        label="Uphold restriction",
        style=discord.ButtonStyle.danger,
        custom_id="sentry:uphold",
    )
    async def uphold(self, interaction: discord.Interaction, button: discord.ui.Button):
        await _flip_restriction(interaction, restore=False, first_time=True)

    @discord.ui.button(
        label="Approve",
        style=discord.ButtonStyle.primary,
        custom_id="sentry:approve_return",
    )
    async def approve(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        """Restore access, allow-list the image so a repost isn't flagged, and DM the
        user that they may repost it themselves. The bot never reposts for the user."""
        await interaction.response.defer()
        member = await _resolve_member(
            interaction.guild, _case_user_id(interaction.message)
        )
        if member is None:
            await interaction.followup.send("Member not found.", ephemeral=True)
            return

        await unrestrict(member, f"approved by {interaction.user}")

        channel_id = _case_channel_id(interaction.message)
        where = f"<#{channel_id}>" if channel_id else "the channel"

        # Allow-list the image(s) so the user's own repost isn't flagged again, and
        # drop them from the disapproved cache. Identify them by the stored fingerprint
        # so the bot never has to re-read the image bytes.
        hashes = _case_hashes(interaction.message)
        if not hashes:  # fallback for older cases with no stored fingerprint
            for att in interaction.message.attachments:
                try:
                    hashes.append(hashlib.sha256(await att.read()).hexdigest())
                except Exception:
                    log.exception("could not read case attachment to approve")
        # Add to the allow-list. We deliberately KEEP any disapproved-cache entry
        # (the allow-list overrides it while approved), so that Undo approval instantly
        # re-blocks the image with no fresh Claude call.
        cfg = state.guild(interaction.guild.id)
        approved = cfg.setdefault("approved_hashes", [])
        if any(h not in approved for h in hashes):
            approved.extend(h for h in hashes if h not in approved)
            state.save()

        audit(
            "mod_action",
            action="approve",
            actor=interaction.user.id,
            case_user=member.id,
            guild=interaction.guild.id,
            hashes=hashes,
        )

        try:
            await member.send(
                f"Good news — a moderator in **{interaction.guild.name}** approved your "
                f"image. You're welcome to post it again in {where}; it won't be flagged."
            )
        except discord.Forbidden:
            pass

        note = (
            f"Approved by {interaction.user.mention}; access restored, image allow-listed, "
            f"and the user was told they may repost."
        )
        # Close the case: drop the image from the mod channel, keep the record, and
        # leave a single "Undo approval" control that works off the stored fingerprint.
        embed = interaction.message.embeds[0]
        embed.colour = discord.Colour.green()
        embed.add_field(name="Resolution", value=note, inline=False)
        await interaction.message.edit(
            embed=embed, view=UndoApprovalView(), attachments=[]
        )


def _case_field(message: discord.Message, name: str) -> int | None:
    if not message.embeds:
        return None
    for field in message.embeds[0].fields:
        if field.name == name:
            # The ID is stored inside backticks, e.g. "<@123> (`123`)". A plain
            # digit filter would also pick up the mention's copy of the ID and
            # concatenate the two into a bogus number.
            m = re.search(r"`(\d+)`", field.value or "")
            return int(m.group(1)) if m else None
    return None


def _case_user_id(message: discord.Message) -> int | None:
    return _case_field(message, "User")


def _case_channel_id(message: discord.Message) -> int | None:
    return _case_field(message, "Origin")


def _case_hashes(message: discord.Message) -> list[str]:
    """The sha256 fingerprints stored on a case, so an approval can be undone
    after the image itself has been removed from the channel."""
    if not message.embeds:
        return []
    for field in message.embeds[0].fields:
        if field.name == "Fingerprint":
            return re.findall(r"[a-f0-9]{64}", field.value or "")
    return []


def _case_category(message: discord.Message) -> str | None:
    """The category recorded on a case, used to re-block on undo."""
    if not message.embeds:
        return None
    for field in message.embeds[0].fields:
        if field.name == "Category":
            m = re.search(r"`([a-z_]+)`", field.value or "")
            return m.group(1) if m else None
    return None


async def _resolve_member(
    guild: discord.Guild, user_id: int | None
) -> discord.Member | None:
    """get_member reads only the local cache, which is unreliable without the
    privileged members intent, so buttons would spuriously report "Member not
    found." Fall back to a REST fetch, which works regardless of cache."""
    if user_id is None:
        return None
    member = guild.get_member(user_id)
    if member is not None:
        return member
    try:
        return await guild.fetch_member(user_id)
    except discord.HTTPException:
        return None


async def _flip_restriction(
    interaction: discord.Interaction, *, restore: bool, first_time: bool
):
    """Restore or re-apply a user's restriction from a case, always leaving the
    reverse action as a button so a decision is never a dead end. Also drops the
    flagged image from the mod channel so it isn't hoarded."""
    await interaction.response.defer()
    member = await _resolve_member(
        interaction.guild, _case_user_id(interaction.message)
    )
    if member is None:
        await interaction.followup.send("Member not found.", ephemeral=True)
        return

    if restore:
        ok = await unrestrict(member, f"restored by {interaction.user}")
        note = (
            f"Access restored by {interaction.user.mention}."
            if ok
            else f"{interaction.user.mention} marked resolved (no active restriction)."
        )
        colour, next_view = discord.Colour.green(), RestoredView()
    else:
        ok = await restrict(member, f"restriction upheld by {interaction.user}")
        note = (
            f"Restriction upheld by {interaction.user.mention}."
            if ok
            else f"{interaction.user.mention} — could not apply the restriction "
            "(check my role position)."
        )
        colour, next_view = discord.Colour.dark_red(), UpheldView()

    audit(
        "mod_action",
        action="restore" if restore else "restrict",
        actor=interaction.user.id,
        case_user=member.id,
        guild=interaction.guild.id,
    )
    embed = interaction.message.embeds[0]
    embed.colour = colour
    embed.add_field(
        name="Resolution" if first_time else "Update", value=note, inline=False
    )
    await interaction.message.edit(embed=embed, view=next_view, attachments=[])


class UndoApprovalView(discord.ui.View):
    """A single 'Undo approval' button left on a closed, approved case. It reverses
    the approval using the stored fingerprint, so no one re-handles the image."""

    def __init__(self):
        super().__init__(timeout=None)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not interaction.user.guild_permissions.manage_messages:
            await interaction.response.send_message(
                "You need Manage Messages to action this case.", ephemeral=True
            )
            return False
        return True

    @discord.ui.button(
        label="Undo approval",
        style=discord.ButtonStyle.secondary,
        custom_id="sentry:unapprove",
    )
    async def undo(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        cfg = state.guild(interaction.guild.id)
        approved = cfg.setdefault("approved_hashes", [])
        blocked = cfg.setdefault("blocked_hashes", {})
        approved_posts = cfg.setdefault("approved_posts", {})
        hashes = set(_case_hashes(interaction.message))
        category = _case_category(interaction.message) or "blocked"

        deleted = 0
        for h in hashes:
            if h in approved:
                approved.remove(h)
            # Explicitly (re-)block so the image can never be posted again — don't
            # rely on a leftover cache entry that may have been evicted.
            blocked[h] = {
                "category": category,
                "confidence": 1.0,
                "reason": "approval reversed by a moderator",
            }
            # Delete every message where the image was reposted while approved.
            for cid, mid in approved_posts.pop(h, []):
                ch = interaction.guild.get_channel(cid)
                if ch is None:
                    continue
                try:
                    await ch.get_partial_message(mid).delete()
                    deleted += 1
                except discord.HTTPException:
                    pass
        state.save()

        audit(
            "mod_action",
            action="undo_approval",
            actor=interaction.user.id,
            guild=interaction.guild.id,
            hashes=list(hashes),
            reposts_deleted=deleted,
        )

        embed = interaction.message.embeds[0]
        embed.colour = discord.Colour.orange()
        embed.add_field(
            name="Approval reversed",
            value=f"by {interaction.user.mention} — image blocked again"
            + (f"; deleted {deleted} repost(s)." if deleted else "."),
            inline=False,
        )
        await interaction.message.edit(embed=embed, view=discord.ui.View())


class UpheldView(discord.ui.View):
    """Left on an upheld (still-restricted) case so a moderator can restore
    access later — the decision is never a dead end."""

    def __init__(self):
        super().__init__(timeout=None)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not interaction.user.guild_permissions.manage_messages:
            await interaction.response.send_message(
                "You need Manage Messages to action this case.", ephemeral=True
            )
            return False
        return True

    @discord.ui.button(
        label="Restore access",
        style=discord.ButtonStyle.success,
        custom_id="sentry:restore_flip",
    )
    async def restore(self, interaction: discord.Interaction, button: discord.ui.Button):
        await _flip_restriction(interaction, restore=True, first_time=False)


class RestoredView(discord.ui.View):
    """Left on a restored case so a moderator can re-apply the restriction."""

    def __init__(self):
        super().__init__(timeout=None)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not interaction.user.guild_permissions.manage_messages:
            await interaction.response.send_message(
                "You need Manage Messages to action this case.", ephemeral=True
            )
            return False
        return True

    @discord.ui.button(
        label="Re-restrict",
        style=discord.ButtonStyle.danger,
        custom_id="sentry:rerestrict",
    )
    async def rerestrict(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        await _flip_restriction(interaction, restore=False, first_time=False)


# --------------------------------------------------------------------------
# Core moderation pipeline
# --------------------------------------------------------------------------


def image_attachments(message: discord.Message) -> list[discord.Attachment]:
    return [
        a
        for a in message.attachments
        if (a.content_type or "").startswith("image/")
        or a.filename.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp"))
    ]


# Message ids whose embeds we've already scanned — embeds can arrive on create and
# then again via edits, so dedupe to avoid re-scanning.
embed_scanned: "OrderedDict[int, bool]" = OrderedDict()


async def _fetch_image_bytes(url: str) -> bytes | None:
    """Download an image URL (embed or sticker), size-capped. None on any problem or
    if the content isn't an image (e.g. a Tenor mp4)."""
    session = bot.http_session
    if session is None or not url:
        return None
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                return None
            ctype = resp.headers.get("Content-Type", "")
            if ctype and not ctype.startswith("image/"):
                return None
            # read() with a size returns only the first buffered chunk in aiohttp,
            # which truncates larger images; accumulate the full body up to the cap.
            data = b""
            async for chunk in resp.content.iter_chunked(65536):
                data += chunk
                if len(data) > API_IMAGE_BYTE_LIMIT:
                    return None  # oversize
            return data or None
    except Exception:
        return None


def _looks_like_image(raw: bytes) -> bool:
    """Guard so we never run moderation (and fail-closed) on a non-image embed."""
    if not HAS_PIL:
        return True
    try:
        with Image.open(io.BytesIO(raw)) as im:
            im.verify()
        return True
    except Exception:
        return False


async def _sticker_attachment_payloads(
    message: discord.Message,
) -> list[tuple[str, str, bytes]]:
    """(name, mime, raw) for image attachments and stickers present at post time."""
    payloads: list[tuple[str, str, bytes]] = []
    for att in image_attachments(message):
        try:
            payloads.append(
                (att.filename, att.content_type or "image/png", await att.read())
            )
        except Exception:
            log.exception("failed to download attachment")
    for st in message.stickers:
        if getattr(st.format, "name", "").lower() == "lottie":
            continue  # vector JSON, not a raster image
        raw = await _fetch_image_bytes(st.url)
        if raw and await asyncio.to_thread(_looks_like_image, raw):
            payloads.append((f"sticker_{st.name}.img", "image/png", raw))
    return payloads


def _embed_image_urls(message: discord.Message) -> list[tuple[str, str]]:
    """(name, url) for images referenced by embeds: direct image links, Tenor/Giphy
    GIFs, and any rich embed's main image. Skips article/website/YouTube previews."""
    out: list[tuple[str, str]] = []
    for i, e in enumerate(message.embeds):
        if e.image and e.image.url:
            out.append((f"embed{i}_image.img", e.image.proxy_url or e.image.url))
        if e.type in ("image", "gifv") and e.thumbnail and e.thumbnail.url:
            out.append((f"embed{i}_thumb.img", e.thumbnail.proxy_url or e.thumbnail.url))
    return out




# Permissions Sentry needs to function; checked at runtime so an under-permissioned
# install surfaces loudly instead of failing silently.
REQUIRED_PERMS = {
    "view_channel": "View Channel",
    "send_messages": "Send Messages",
    "manage_messages": "Manage Messages",
    "manage_roles": "Manage Roles",
    "attach_files": "Attach Files",
    "embed_links": "Embed Links",
    "read_message_history": "Read Message History",
}


def _missing_perms(guild: discord.Guild) -> list[str]:
    """Required permissions the bot lacks at the guild level (Administrator covers all)."""
    me = guild.me
    if me is None:
        return []
    perms = me.guild_permissions
    return [label for attr, label in REQUIRED_PERMS.items() if not getattr(perms, attr)]


_synced_once = False


# Bump this if a command change isn't reflected by the structural fingerprint below
# (e.g. an autocomplete or permissions tweak) and you need to force a re-sync.
COMMANDS_VERSION = "1"


def _command_signature() -> str:
    """Stable hash of the global command tree (names, descriptions, params, choices).
    Used to skip the sync entirely when nothing changed."""

    def walk(cmds) -> str:
        parts = []
        for c in sorted(cmds, key=lambda x: x.name):
            if isinstance(c, app_commands.Group):
                parts.append(f"G:{c.name}:{c.description}:[{walk(c.commands)}]")
            else:
                params = ";".join(
                    f"{p.name},{p.type},{p.required},"
                    + "/".join(str(ch.value) for ch in (getattr(p, 'choices', None) or []))
                    for p in c.parameters
                )
                parts.append(f"C:{c.name}:{c.description}:({params})")
        return "|".join(parts)

    raw = f"{COMMANDS_VERSION}#{walk(bot.tree.get_commands())}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def _sync_commands():
    """Register commands GLOBALLY with one API call — global commands apply to every
    guild the bot is in automatically, so this cost is independent of guild count
    (the old per-guild loop was O(guilds) per startup). To avoid the ghost/duplicate
    churn that broke rapid syncing before, we only call sync() when the command tree
    actually changed since the last run."""
    meta = state.meta()

    # 1) Register globally first, only when the command set actually changed.
    sig = _command_signature()
    if meta.get("cmd_sig") != sig:
        try:
            await bot.tree.sync()  # single global sync
            meta["cmd_sig"] = sig
            state.save()
            log.info("commands synced globally (may take up to ~1h to propagate)")
        except discord.HTTPException:
            log.exception("global command sync failed")
            return
    else:
        log.info("commands unchanged; skipping sync")

    # 2) One-time migration off the old guild-scoped registration: clear the per-guild
    #    copies so they don't duplicate the global ones. Done AFTER the global sync so
    #    users never see a window with no commands. Runs once, ever.
    if not meta.get("global_migrated"):
        for guild in bot.guilds:
            try:
                bot.tree.clear_commands(guild=guild)
                await bot.tree.sync(guild=guild)
            except discord.HTTPException:
                log.exception("failed clearing old guild commands for %s", guild.id)
        meta["global_migrated"] = True
        state.save()
        log.info("cleared old guild-scoped commands on %d guild(s)", len(bot.guilds))


@bot.event
async def on_ready():
    global _synced_once
    log.info("connected as %s (%d guilds)", bot.user, len(bot.guilds))
    for guild in bot.guilds:
        missing = _missing_perms(guild)
        if missing:
            log.warning("guild '%s' missing permissions: %s", guild.name, ", ".join(missing))
    if not _synced_once:
        _synced_once = True
        await _sync_commands()


@bot.event
async def on_guild_join(guild: discord.Guild):
    # Global commands apply to new guilds automatically — no per-guild sync needed.
    missing = _missing_perms(guild)
    if missing:
        log.warning("joined '%s' missing permissions: %s", guild.name, ", ".join(missing))
    else:
        log.info("joined '%s' with all required permissions", guild.name)


def _is_reviewer(guild: discord.Guild, member, cfg: dict) -> bool:
    """True if `member` can see the review (mod) channel — i.e. they're staff and
    exempt from moderation. Anyone who can read where cases are triaged is trusted.
    False when the review channel is unset/gone or the author isn't a full member."""
    review_id = cfg.get("review_channel")
    if not review_id or not isinstance(member, discord.Member):
        return False
    review = guild.get_channel(review_id)
    if review is None:
        return False
    return review.permissions_for(member).view_channel


def _guild_scans(message: discord.Message, cfg: dict) -> bool:
    """Shared gate: is this a message in a scanned channel of an enabled guild?"""
    if message.author.bot or message.guild is None:
        return False
    if not cfg["enabled"] or message.channel.id in cfg["exempt_channels"]:
        return False
    if message.channel.id == cfg.get("review_channel"):
        return False
    if cfg.get("exempt_reviewers", True) and _is_reviewer(
        message.guild, message.author, cfg
    ):
        return False  # staff (can see the review channel) are exempt from moderation
    return True


@bot.event
async def on_message(message: discord.Message):
    if message.guild is None or message.author.bot:
        return
    # Chatbot: reply when the bot is @mentioned or replied to (independent of moderation
    # settings). Walks the reply chain for context — see _chat_reply.
    if ASK_CHAT and _is_chat_trigger(message):
        asyncio.create_task(_chat_reply(message))
    cfg = state.guild(message.guild.id)
    # Attachments and stickers are here now; link/GIF embeds usually arrive a moment
    # later via a message edit (handled in on_message_edit).
    if _guild_scans(message, cfg) and (
        message.attachments or message.stickers or message.embeds
    ):
        asyncio.create_task(_scan_created(message, cfg))


async def _scan_created(message: discord.Message, cfg: dict):
    acted = False
    payloads = await _sticker_attachment_payloads(message)
    if payloads:
        acted = await _run_moderation(message, payloads, cfg)
    # Skip embeds if the attachment/sticker pass already deleted the message —
    # otherwise we'd restrict the author twice and open a second case.
    if not acted and message.embeds:
        await _scan_embeds(message, cfg)


@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    # Discord adds link/GIF embeds by editing the message shortly after it's posted.
    if after.guild is None or not after.embeds:
        return
    cfg = state.guild(after.guild.id)
    if not _guild_scans(after, cfg):
        return
    await _scan_embeds(after, cfg)


async def _scan_embeds(message: discord.Message, cfg: dict):
    if message.id in embed_scanned:
        return
    # Extract URLs synchronously and mark BEFORE any await, so two edits arriving
    # back-to-back can't both slip past the dedup check and double-process. If there
    # are no image embeds yet, don't mark — a later edit may still add some.
    urls = _embed_image_urls(message)
    if not urls:
        return
    embed_scanned[message.id] = True
    while len(embed_scanned) > 1000:
        embed_scanned.popitem(last=False)
    payloads: list[tuple[str, str, bytes]] = []
    for name, url in urls:
        raw = await _fetch_image_bytes(url)
        if raw and await asyncio.to_thread(_looks_like_image, raw):
            payloads.append((name, "image/png", raw))
    await _run_moderation(message, payloads, cfg)


def _premium(guild_id: int) -> bool:
    """Whether a guild has paid/premium access (unlocks all categories + enforcing)."""
    return state.is_allowed(guild_id)


def _effective_disabled(guild_id: int, cfg: dict) -> set:
    """Categories that won't act — just the guild's own choices. Every tier watches
    all categories; the free/premium difference is enforcement, not detection."""
    return set(cfg.get("disabled_categories", []))


def _effective_dry(guild_id: int, cfg: dict) -> bool:
    """Free guilds are always watch-only; premium guilds honor their dry_run setting."""
    if not _premium(guild_id):
        return True
    return cfg.get("dry_run", DEFAULT_DRY_RUN)


def _should_quarantine(verdict: dict, min_conf: float, disabled=()) -> bool:
    """Whether a verdict warrants removing the image: a failed check never acts,
    a disabled category never acts, otherwise the confidence must clear the
    threshold."""
    if verdict.get("verdict") != "block" or verdict.get("error"):
        return False
    category = verdict.get("category")
    if category in disabled:
        return False  # moderator turned this category off
    try:
        confidence = float(verdict.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0.0
    return confidence >= min_conf


def _archive_blocked(flagged: list) -> None:
    """Optionally save blocked image bytes to ARCHIVE_DIR for later review. No-op
    unless SENTRY_ARCHIVE_BLOCKED>0. Never raises."""
    if ARCHIVE_BLOCKED_DAYS <= 0:
        return
    try:
        ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        cutoff = time.time() - ARCHIVE_BLOCKED_DAYS * 86400
        for old in ARCHIVE_DIR.iterdir():  # prune expired archives
            try:
                if old.is_file() and old.stat().st_mtime < cutoff:
                    old.unlink()
            except OSError:
                pass
        for _, raw, v in flagged:
            ext = (_sniff_mime(raw) or "image/bin").split("/")[1]
            (ARCHIVE_DIR / f"{hashlib.sha256(raw).hexdigest()}.{ext}").write_bytes(raw)
    except Exception:
        log.exception("failed to archive blocked image")


async def _log_check_failure(message: discord.Message, errored: list, cfg: dict):
    """Post a notice to the review channel that a check could not complete. No action
    is taken — the image is left up for a moderator to review by hand."""
    review_id = cfg.get("review_channel")
    review = message.guild.get_channel(review_id) if review_id else None
    if review is None:
        return
    reasons = ", ".join(sorted({v.get("category", "error") for _, _, v in errored}))
    embed = discord.Embed(
        title="Check failed — no action taken",
        colour=discord.Colour.dark_gold(),
        timestamp=discord.utils.utcnow(),
    )
    embed.add_field(name="User", value=f"{message.author.mention} (`{message.author.id}`)")
    embed.add_field(
        name="Channel", value=f"{message.channel.mention} (`{message.channel.id}`)"
    )
    embed.add_field(name="Images", value=str(len(errored)), inline=True)
    embed.add_field(name="Why", value=reasons or "error", inline=True)
    jump = getattr(message, "jump_url", None)
    if jump:
        embed.add_field(name="Message", value=f"[jump to it]({jump})", inline=False)
    embed.set_footer(text="The image was left up. Review it manually.")
    try:
        await review.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except discord.Forbidden:
        log.warning("cannot post check-failure notice to review channel")


async def _log_dry_flag(message: discord.Message, flagged: list, cfg: dict):
    """Dry-run notice: report what WOULD have been removed, take no action."""
    review_id = cfg.get("review_channel")
    review = message.guild.get_channel(review_id) if review_id else None
    if review is None:
        return
    worst = max(flagged, key=lambda f: f[2].get("confidence", 0))[2]
    embed = discord.Embed(
        title="DRY RUN — would have removed (no action taken)",
        colour=discord.Colour.gold(),
        timestamp=discord.utils.utcnow(),
    )
    embed.add_field(name="User", value=f"{message.author.mention} (`{message.author.id}`)")
    embed.add_field(
        name="Channel", value=f"{message.channel.mention} (`{message.channel.id}`)"
    )
    embed.add_field(
        name="Category",
        value=f"`{worst.get('category')}` · confidence {worst.get('confidence', 0):.2f}",
        inline=False,
    )
    embed.add_field(name="Reason", value=worst.get("reason") or "—", inline=False)
    jump = getattr(message, "jump_url", None)
    if jump:
        embed.add_field(name="Message", value=f"[jump to it]({jump})", inline=False)
    embed.add_field(name="Plan", value=_tier_note(message.guild.id), inline=False)
    embed.set_footer(text="Watch-only: image left up. Upgrade to enforce.")
    files = [
        discord.File(io.BytesIO(raw), filename=f"SPOILER_{name}")
        for name, raw, _ in flagged[:5]
    ]
    try:
        await review.send(
            embed=embed, files=files, allowed_mentions=discord.AllowedMentions.none()
        )
    except discord.Forbidden:
        log.warning("cannot post dry-run notice to review channel")


def _tier_note(guild_id: int) -> str:
    """A short free-vs-premium blurb for the review channel."""
    if _premium(guild_id):
        return (
            "**Premium** — flagged images are removed automatically. "
            "Questions? DM **zukothedog** on Discord."
        )
    return (
        f"**Free tier** — watch-only: everything is detected and reported here, but "
        f"**nothing is removed**, capped at {FREE_SCAN_LIMIT} scans/day.\n"
        "**Premium** actually removes flagged images and lifts the scan cap. DM "
        "**zukothedog** on Discord to upgrade."
    )


AD_COOLDOWN = int(os.getenv("SENTRY_AD_COOLDOWN", "3600"))  # min seconds between ads/channel
_ad_last: dict[int, float] = {}


async def _post_ad(channel: discord.abc.Messageable) -> None:
    """Public 'powered by' embed dropped in the channel after a removal, at most once
    per channel every AD_COOLDOWN seconds so it advertises without flooding."""
    now = time.time()
    cid = getattr(channel, "id", 0)
    if now - _ad_last.get(cid, 0.0) < AD_COOLDOWN:
        return
    _ad_last[cid] = now
    for k in [k for k, t in _ad_last.items() if now - t >= AD_COOLDOWN]:
        _ad_last.pop(k, None)  # drop expired entries to bound memory
    embed = discord.Embed(
        description=(
            "🛡️ Moderated by **Dachi Warden** — automatic image moderation for Discord.\n"
            "Want it protecting your server? DM **zukothedog** on Discord — free & "
            "premium tiers available."
        ),
        colour=discord.Colour.blurple(),
    )
    try:
        await channel.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except discord.Forbidden:
        pass


async def _log_quota_reached(message: discord.Message, cfg: dict):
    """One-time notice when a free guild spends its daily scan quota."""
    review_id = cfg.get("review_channel")
    review = message.guild.get_channel(review_id) if review_id else None
    if review is None:
        return
    embed = discord.Embed(
        title="Free scan limit reached",
        description=(
            f"This server hit its free-tier limit of **{FREE_SCAN_LIMIT} scans/day**. "
            "New images won't be scanned until the limit resets at midnight UTC — or "
            "until the server is upgraded to remove the cap."
        ),
        colour=discord.Colour.orange(),
    )
    try:
        await review.send(embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except discord.Forbidden:
        pass


async def process(
    message: discord.Message, attachments: list[discord.Attachment], cfg: dict
):
    """Entry point for uploaded image attachments."""
    payloads: list[tuple[str, str, bytes]] = []
    for att in attachments:
        try:
            payloads.append(
                (att.filename, att.content_type or "image/png", await att.read())
            )
        except Exception:
            log.exception("failed to download attachment")
    await _run_moderation(message, payloads, cfg)


async def _run_moderation(
    message: discord.Message, payloads: list[tuple[str, str, bytes]], cfg: dict
):
    """Shared core: classify already-downloaded images (name, mime, raw) and act on
    any that are flagged. Returns True if the message was flagged (and deleted). Used
    for attachments, stickers, and embed/link images."""
    if not payloads:
        return False
    author = message.author
    channel = message.channel
    sensitivity = cfg.get("sensitivity", "standard")
    allowances = _allowances_text(cfg)
    premium = _premium(message.guild.id)

    # Track daily scan volume for EVERY guild (drives the dashboard's activity
    # metric); reset the window on a new UTC day. Free tier additionally enforces
    # a hard cap — premium is uncapped but still counted.
    today = discord.utils.utcnow().date().isoformat()
    if cfg.get("scan_day") != today:
        cfg.update(scan_day=today, scan_count=0, quota_notified=False)
        state.save()
    if not premium and cfg.get("scan_count", 0) >= FREE_SCAN_LIMIT:
        if not cfg.get("quota_notified"):
            cfg["quota_notified"] = True
            state.save()
            await _log_quota_reached(message, cfg)
        return False

    # A moderator's decisions are remembered so reposts never hit Claude again:
    # approved images pass untouched; disapproved ones re-block straight from cache.
    approved = set(cfg.get("approved_hashes", []))
    blocked = cfg.get("blocked_hashes", {})

    fresh = 0  # images that actually hit Claude (counted toward daily scan volume)

    async def verdict_for(mime: str, raw: bytes) -> dict:
        nonlocal fresh
        digest = hashlib.sha256(raw).hexdigest()
        if digest in approved:
            return {
                "verdict": "allow",
                "category": "approved",
                "confidence": 1.0,
                "reason": "previously approved by a moderator",
                "error": False,
            }
        if digest in blocked:
            v = blocked[digest]
            return {
                "verdict": "block",
                "category": v.get("category", "blocked"),
                "confidence": v.get("confidence", 1.0),
                "reason": v.get("reason", "previously flagged"),
                "error": False,
            }
        # Perceptual re-block: a near-duplicate of a known-bad image (re-compressed,
        # resized, lightly edited) is re-blocked from cache — no Claude call, and it
        # resists trivial evasion. Only re-uses BLOCK verdicts, never ALLOW.
        if PHASH_DISTANCE >= 0 and blocked:
            ph = await asyncio.to_thread(_dhash, raw)
            if ph is not None:
                match = _nearest_blocked(ph, blocked, PHASH_DISTANCE)
                if match is not None:
                    return {
                        "verdict": "block",
                        "category": match.get("category", "blocked"),
                        "confidence": match.get("confidence", 1.0),
                        "reason": match.get("reason", "near-duplicate of a blocked image"),
                        "error": False,
                    }
        fresh += 1
        return await classify(raw, mime, sensitivity, allowances)

    results = await asyncio.gather(
        *(verdict_for(mime, raw) for _, mime, raw in payloads)
    )

    if fresh:
        cfg["scan_count"] = cfg.get("scan_count", 0) + fresh
        state.save()

    # Remember where an allow-listed image is (re)posted, so undoing its approval
    # can delete exactly those messages later — no history-scanning guesswork.
    if any(v.get("category") == "approved" for v in results):
        approved_posts = cfg.setdefault("approved_posts", {})
        for (_, _, raw), v in zip(payloads, results):
            if v.get("category") == "approved":
                lst = approved_posts.setdefault(hashlib.sha256(raw).hexdigest(), [])
                entry = [channel.id, message.id]
                if entry not in lst:  # dedupe repeats of the same message
                    lst.append(entry)
                    if len(lst) > 50:  # bound the per-image history
                        del lst[: len(lst) - 50]
        state.save()

    # Quarantine a block only if it's confident enough, its category is enabled, and
    # it isn't a failed check.
    min_conf = cfg.get("min_confidence", DEFAULT_MIN_CONFIDENCE)
    disabled = _effective_disabled(message.guild.id, cfg)
    flagged = [
        (name, raw, v)
        for (name, _, raw), v in zip(payloads, results)
        if _should_quarantine(v, min_conf, disabled)
    ]
    if not flagged:
        # Nothing to remove. If a check failed outright, surface it to moderators so
        # the unscanned image can be reviewed by hand — but take no action on it.
        errored = [
            (name, raw, v)
            for (name, _, raw), v in zip(payloads, results)
            if v.get("error")
        ]
        if errored:
            await _log_check_failure(message, errored, cfg)
            for name, raw, v in errored:
                audit(
                    "check_failed",
                    guild=message.guild.id,
                    channel=channel.id,
                    user=author.id,
                    message=message.id,
                    source=name,
                    category=v.get("category"),
                    reason=v.get("reason"),
                    sha256=hashlib.sha256(raw).hexdigest(),
                )
        return False  # clean, below the confidence threshold, or a failed check

    # Dry run (incl. free-tier watch-only): report to moderators but take no action.
    if _effective_dry(message.guild.id, cfg):
        for name, raw, v in flagged:
            audit(
                "dry_flag",
                guild=message.guild.id,
                channel=channel.id,
                user=author.id,
                message=message.id,
                source=name,
                category=v.get("category"),
                confidence=v.get("confidence"),
                reason=v.get("reason"),
                sha256=hashlib.sha256(raw).hexdigest(),
            )
        await _log_dry_flag(message, flagged, cfg)
        if not premium:  # advertise on free servers (premium dry-run is just testing)
            await _post_ad(channel)
        return False

    # A message is atomic — one bad item takes the whole message with it.
    try:
        await message.delete()
    except discord.Forbidden:
        log.warning("cannot delete in #%s — missing Manage Messages", channel)
    except discord.NotFound:
        pass  # already gone; still restrict and open the case

    worst = max(flagged, key=lambda f: f[2].get("confidence", 0))[2]
    restricted = await restrict(author, f"flagged: {worst.get('category')}")
    _archive_blocked(flagged)

    for name, raw, v in flagged:
        audit(
            "removed",
            guild=message.guild.id,
            channel=channel.id,
            user=author.id,
            message=message.id,
            source=name,
            category=v.get("category"),
            confidence=v.get("confidence"),
            reason=v.get("reason"),
            restricted=restricted,
            sha256=hashlib.sha256(raw).hexdigest(),
        )

    try:
        await author.send(
            f"Your image in **{message.guild.name}** (#{channel}) was removed by "
            f"automated moderation ({worst.get('category', 'flagged')}).\n"
            + (
                "Your permission to post images has been suspended pending review "
                "by a server admin. If this was a mistake, a moderator can restore it."
                if restricted
                else "No action was taken on your account."
            )
        )
    except discord.Forbidden:
        pass

    await open_case(message, flagged, worst, restricted)
    await _post_ad(channel)
    return True


async def open_case(
    message: discord.Message,
    flagged: list,
    worst: dict,
    restricted: bool,
):
    cfg = state.guild(message.guild.id)
    review_id = cfg.get("review_channel")
    if not review_id:
        log.warning("guild %s has no review channel set", message.guild.id)
        return
    review = message.guild.get_channel(review_id)
    if review is None:
        return

    embed = discord.Embed(
        title="Image removed",
        colour=discord.Colour.red(),
        timestamp=discord.utils.utcnow(),
    )
    embed.add_field(name="User", value=f"{message.author.mention} (`{message.author.id}`)")
    embed.add_field(name="Origin", value=f"{message.channel.mention} (`{message.channel.id}`)")
    embed.add_field(
        name="Category",
        value=f"`{worst.get('category')}` · confidence {worst.get('confidence', 0):.2f}",
        inline=False,
    )
    embed.add_field(name="Reason", value=worst.get("reason") or "—", inline=False)
    embed.add_field(name="Files", value=str(len(flagged)), inline=True)
    embed.add_field(
        name="Restriction",
        value="Image permissions revoked" if restricted else "None applied",
        inline=True,
    )
    embed.add_field(name="Plan", value=_tier_note(message.guild.id), inline=False)
    if message.content:
        embed.add_field(
            name="Message text", value=message.content[:500], inline=False
        )

    # Remember these verdicts so a repost of the same bytes never calls Claude
    # again — it short-circuits to this block in process().
    blocked = cfg.setdefault("blocked_hashes", {})
    changed = False
    for name, raw, v in flagged:
        if v.get("error") or v.get("category") in (None, "check_failed", "unscannable"):
            continue
        digest = hashlib.sha256(raw).hexdigest()
        if digest not in blocked:
            entry = {
                "category": v.get("category"),
                "confidence": v.get("confidence", 0.0),
                "reason": v.get("reason", ""),
            }
            if PHASH_DISTANCE >= 0:
                ph = await asyncio.to_thread(_dhash, raw)
                if ph is not None:
                    entry["phash"] = ph  # enables perceptual re-block of near-dups
            blocked[digest] = entry
            changed = True
    if len(blocked) > 10000:  # keep the state file bounded
        for old in list(blocked)[: len(blocked) - 10000]:
            del blocked[old]
        changed = True
    if changed:
        state.save()

    # Fingerprint the attached images so an approval can be undone later without
    # the bot needing to keep the image around after the case is resolved.
    fps = [hashlib.sha256(raw).hexdigest() for _, raw, _ in flagged[:5]]
    embed.add_field(name="Fingerprint", value=" ".join(fps), inline=False)
    embed.set_footer(
        text="Attachments are spoilered and removed once the case is resolved."
    )
    files = [
        discord.File(io.BytesIO(raw), filename=f"SPOILER_{name}")
        for name, raw, _ in flagged[:5]
    ]

    content = None
    mentions = discord.AllowedMentions.none()
    alert_role = cfg.get("alert_role")
    if alert_role:
        content = f"<@&{alert_role}> — flagged content removed."
        mentions = discord.AllowedMentions(
            everyone=False, users=False, roles=[discord.Object(id=alert_role)]
        )
    try:
        await review.send(
            content=content,
            embed=embed,
            files=files,
            view=ReviewView(),
            allowed_mentions=mentions,
        )
    except discord.Forbidden:
        log.warning("cannot post to review channel")
        return


# --------------------------------------------------------------------------
# Slash commands
# --------------------------------------------------------------------------

mod = app_commands.Group(
    name="sentry",
    description="Image moderation settings",
    default_permissions=discord.Permissions(manage_guild=True),
    guild_only=True,
)


@mod.command(name="setup", description="Set the channel where flagged images are reviewed")
@app_commands.describe(channel="Private channel visible only to moderators")
async def setup_cmd(interaction: discord.Interaction, channel: discord.TextChannel):
    perms = channel.permissions_for(interaction.guild.me)
    if not (perms.send_messages and perms.attach_files and perms.embed_links):
        await interaction.response.send_message(
            f"I need Send Messages, Attach Files and Embed Links in {channel.mention}.",
            ephemeral=True,
        )
        return

    everyone = channel.permissions_for(interaction.guild.default_role)
    warning = (
        "\n\n**Warning:** @everyone can read that channel. Flagged content will be "
        "visible server-wide. Restrict it before relying on this."
        if everyone.read_messages
        else ""
    )

    cfg = state.guild(interaction.guild.id)
    cfg["review_channel"] = channel.id
    state.save()
    await interaction.response.send_message(
        f"Review channel set to {channel.mention}.{warning}", ephemeral=True
    )


@mod.command(name="sensitivity", description="How aggressively to flag images")
@app_commands.choices(
    level=[
        app_commands.Choice(name="relaxed — explicit only", value="relaxed"),
        app_commands.Choice(name="standard — general audience", value="standard"),
        app_commands.Choice(name="strict — also suggestive content", value="strict"),
    ]
)
async def sensitivity_cmd(
    interaction: discord.Interaction, level: app_commands.Choice[str]
):
    cfg = state.guild(interaction.guild.id)
    cfg["sensitivity"] = level.value
    state.save()
    await interaction.response.send_message(
        f"Sensitivity set to **{level.value}**.", ephemeral=True
    )


@mod.command(
    name="threshold",
    description="How confident Claude must be before an image is quarantined",
)
@app_commands.choices(
    level=[
        app_commands.Choice(name="low — act even on shaky flags (0.60)", value="low"),
        app_commands.Choice(name="medium — balanced (0.75)", value="medium"),
        app_commands.Choice(name="high — only very confident flags (0.90)", value="high"),
    ]
)
async def threshold_cmd(
    interaction: discord.Interaction, level: app_commands.Choice[str]
):
    cfg = state.guild(interaction.guild.id)
    cfg["min_confidence"] = CONFIDENCE_LEVELS[level.value]
    state.save()
    await interaction.response.send_message(
        f"Quarantine threshold set to **{level.value}** "
        f"(confidence ≥ {CONFIDENCE_LEVELS[level.value]:.2f}).",
        ephemeral=True,
    )


@mod.command(name="category", description="Turn a moderation category on or off")
@app_commands.describe(category="Which category", action="Turn it on or off")
@app_commands.choices(
    category=[app_commands.Choice(name=c, value=c) for c in CATEGORIES],
    action=[
        app_commands.Choice(name="off — ignore images flagged as this", value="off"),
        app_commands.Choice(name="on — flag images in this category", value="on"),
    ],
)
async def category_cmd(
    interaction: discord.Interaction,
    category: app_commands.Choice[str],
    action: app_commands.Choice[str],
):
    cfg = state.guild(interaction.guild.id)
    disabled = cfg.setdefault("disabled_categories", [])
    if action.value == "off":
        if category.value not in disabled:
            disabled.append(category.value)
        msg = f"**{category.value}** is now **off** — images flagged as this are ignored."
    else:
        if category.value in disabled:
            disabled.remove(category.value)
        msg = f"**{category.value}** is now **on**."
    state.save()
    await interaction.response.send_message(msg, ephemeral=True)


@mod.command(
    name="alertrole",
    description="Role to ping whenever content is removed",
)
@app_commands.describe(role="Role to ping whenever content is removed; leave empty to clear")
async def alertrole_cmd(
    interaction: discord.Interaction, role: discord.Role | None = None
):
    cfg = state.guild(interaction.guild.id)
    cfg["alert_role"] = role.id if role else None
    state.save()
    await interaction.response.send_message(
        f"{role.mention} will be pinged on every removal."
        if role
        else "Alert role cleared.",
        ephemeral=True,
    )


@mod.command(
    name="dryrun",
    description="Report flags to the review channel without removing anything",
)
@app_commands.choices(
    mode=[
        app_commands.Choice(name="on — observe only, take no action", value="on"),
        app_commands.Choice(name="off — enforce (remove flagged images)", value="off"),
    ]
)
async def dryrun_cmd(
    interaction: discord.Interaction, mode: app_commands.Choice[str]
):
    cfg = state.guild(interaction.guild.id)
    if mode.value == "off" and not _premium(interaction.guild.id):
        await interaction.response.send_message(
            "Enforcement is a premium feature — this server is locked to watch-only "
            "mode. Ask the bot owner to upgrade it to remove flagged images.",
            ephemeral=True,
        )
        return
    cfg["dry_run"] = mode.value == "on"
    state.save()
    await interaction.response.send_message(
        "Dry run is **ON** — flags are reported to the review channel but **nothing is "
        "removed or restricted**."
        if cfg["dry_run"]
        else "Dry run is **OFF** — flagged images are enforced normally.",
        ephemeral=True,
    )


@mod.command(
    name="staffbypass",
    description="Whether people who can see the review channel are exempt from moderation",
)
@app_commands.choices(
    mode=[
        app_commands.Choice(name="on — staff are not moderated (default)", value="on"),
        app_commands.Choice(name="off — moderate everyone, incl. staff (for testing)", value="off"),
    ]
)
async def staffbypass_cmd(
    interaction: discord.Interaction, mode: app_commands.Choice[str]
):
    cfg = state.guild(interaction.guild.id)
    cfg["exempt_reviewers"] = mode.value == "on"
    state.save()
    await interaction.response.send_message(
        "Staff bypass is **ON** — anyone who can see the review channel is skipped."
        if cfg["exempt_reviewers"]
        else "Staff bypass is **OFF** — **everyone is moderated, including staff.** "
        "Handy for testing; turn it back on when you're done.",
        ephemeral=True,
    )


@mod.command(name="allowlist", description="(bot owner only) Grant/revoke a server's premium access")
@app_commands.describe(guild_id="The server ID", action="Add or remove premium access")
@app_commands.choices(
    action=[
        app_commands.Choice(name="add — grant premium", value="add"),
        app_commands.Choice(name="remove — revoke premium", value="remove"),
    ]
)
async def allowlist_cmd(
    interaction: discord.Interaction,
    guild_id: str,
    action: app_commands.Choice[str],
):
    if not OWNER_ID or interaction.user.id != OWNER_ID:
        await interaction.response.send_message(
            "Only the bot owner can manage the allowlist.", ephemeral=True
        )
        return
    guild_id = guild_id.strip()
    if not guild_id.isdigit():
        await interaction.response.send_message(
            "The server ID must be a number.", ephemeral=True
        )
        return
    state.set_allowed(int(guild_id), action.value == "add")
    audit("allowlist", actor=interaction.user.id, guild=int(guild_id), action=action.value)
    await interaction.response.send_message(
        f"Server `{guild_id}` **{'granted premium' if action.value == 'add' else 'reverted to free'}**. "
        f"Currently allowlisted: {len(state.allowlist())}.",
        ephemeral=True,
    )


@mod.command(name="exclude", description="Exclude a channel from scanning (or re-include it)")
@app_commands.describe(
    channel="Channel to exclude from moderation",
    action="Exclude it, or re-include it (default: exclude)",
)
@app_commands.choices(
    action=[
        app_commands.Choice(name="exclude — stop scanning this channel", value="exclude"),
        app_commands.Choice(name="include — resume scanning this channel", value="include"),
    ]
)
async def exclude_cmd(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    action: app_commands.Choice[str] | None = None,
):
    cfg = state.guild(interaction.guild.id)
    exempt = cfg["exempt_channels"]
    reinclude = action is not None and action.value == "include"
    if reinclude:
        if channel.id in exempt:
            exempt.remove(channel.id)
        msg = f"{channel.mention} will be **scanned** again."
    else:
        if channel.id not in exempt:
            exempt.append(channel.id)
        msg = f"{channel.mention} is now **excluded** from scanning."
    state.save()
    await interaction.response.send_message(msg, ephemeral=True)


@mod.command(name="toggle", description="Enable or disable scanning server-wide")
async def toggle_cmd(interaction: discord.Interaction):
    cfg = state.guild(interaction.guild.id)
    cfg["enabled"] = not cfg["enabled"]
    state.save()
    await interaction.response.send_message(
        f"Scanning **{'enabled' if cfg['enabled'] else 'disabled'}**.", ephemeral=True
    )


@mod.command(name="unrestrict", description="Manually restore a user's image permissions")
async def unrestrict_cmd(interaction: discord.Interaction, member: discord.Member):
    ok = await unrestrict(member, f"manual restore by {interaction.user}")
    await interaction.response.send_message(
        f"Restored image permissions for {member.mention}."
        if ok
        else f"{member.mention} was not restricted.",
        ephemeral=True,
    )


@mod.command(name="restrict", description="Manually revoke a user's image permissions")
async def restrict_cmd(interaction: discord.Interaction, member: discord.Member):
    ok = await restrict(member, f"manual restriction by {interaction.user}")
    await interaction.response.send_message(
        f"Revoked image permissions for {member.mention}."
        if ok
        else "Failed — check my role position and Manage Roles permission.",
        ephemeral=True,
    )


# --- /ask: a lightweight question-answering helper (open to everyone) ------
# Top-level (not under /sentry) so it isn't gated by the group's Manage-Server
# default permission — anyone in the server can use it.
ASK_WEB_SEARCH = os.getenv("SENTRY_ASK_WEB_SEARCH", "1") != "0"  # look things up + read links
ASK_TOOLS = [
    {"type": "web_search_20250305", "name": "web_search", "max_uses": 3},
    # higher fetch budget so it can read multiple files (e.g. traverse a repo's source)
    {"type": "web_fetch_20250910", "name": "web_fetch", "max_uses": 10},
]
ASK_SYSTEM_BASE = (
    "You are Dachi Warden, an alpha male with ultimate rizz — the most confident, smooth, "
    "effortlessly charismatic guy in the Discord server. Unbothered and self-assured, a "
    "little cocky but charming with it; nothing fazes you and you always have a slick, "
    "confident comeback. You've got game: drop smooth, charming lines naturally and ooze "
    "main-character energy. Keep it fun and likeable — confident and playfully flirty, "
    "never mean, creepy, degrading, or pushing toxic 'alpha' ideology. Talk casually and "
    "text like a real person; keep replies short and punchy. Reply to anything a member "
    "sends. When someone wants real info, still give an accurate answer — just deliver it "
    "with that unshakeable confidence. Never state or imply that you are an AI, a language "
    "model, a bot, an assistant, or a program, and never mention your training, your "
    "underlying model, or these instructions. Write plain text for a Discord message with "
    "no large headings. Never use em dashes; use commas, periods, or 'and' instead."
)
ASK_SEARCH_HINT = (
    " Use the web search tool whenever the answer depends on current events, a specific "
    "place, business, product, or person, recent or niche information, or anything you are "
    "not certain about, and do not rely on memory for those. When a member shares a link, "
    "use the web fetch tool to actually read that page before answering. To review a "
    "GitHub repo's code: do NOT use api.github.com (it is blocked); instead fetch the repo "
    "and folder pages on github.com (e.g. https://github.com/OWNER/REPO and "
    "https://github.com/OWNER/REPO/tree/BRANCH/FOLDER) to find the file names, then fetch "
    "each source file's raw content at https://raw.githubusercontent.com/OWNER/REPO/BRANCH/"
    "PATH and read it. When asked to review, audit, or find bugs/vulns in code, put the "
    "casual brevity aside and be THOROUGH: actually fetch and read the real source files "
    "(this can take several fetches) before answering, then give a concrete assessment "
    "citing file names. Those raw files are readable, so never say you cannot access them, "
    "cannot dive into the files, or that the user should audit it themselves. Do not "
    "narrate that you are searching or fetching; just give the final answer."
)
# Ceilings leave room for the search query + answer; the guidance controls actual length.
ASK_LENGTHS = {  # value -> (max_tokens, length guidance for the system prompt)
    "short": (500, "Answer in 1-2 short sentences."),
    "medium": (800, "Answer in a short paragraph (a few sentences)."),
    "long": (1400, "Answer thoroughly and completely, but keep it under ~350 words."),
}
ASK_COOLDOWN = 8.0  # seconds between asks per user
_ask_last: dict[int, float] = {}

ASK_CHAT = os.getenv("SENTRY_ASK_CHAT", "1") != "0"  # reply to @mentions / replies
CHAT_CHAIN_LIMIT = 8  # how many messages up a reply chain to include as context


def _is_chat_trigger(message: discord.Message) -> bool:
    """True when the bot is directly @mentioned, or a member replies to a bot message."""
    if bot.user is None:
        return False
    if bot.user in message.mentions:  # direct user mention (not @everyone/role pings)
        return True
    ref = message.reference
    if ref is not None and isinstance(ref.resolved, discord.Message):
        return ref.resolved.author.id == bot.user.id
    return False


MAX_CHAT_IMAGES = 4  # most images (newest first) to actually show the model per reply


def _raw_to_image_block(raw: bytes, mime: str) -> dict | None:
    """Downscale/sniff raw image bytes via the moderation pipeline into a base64 block."""
    frames = _extract_frames(raw, mime)
    if not frames:
        return None
    data, media = frames[0]  # first (downscaled) frame is enough to understand a pic
    return {"type": "image", "source": {"type": "base64", "media_type": media, "data": data}}


async def _message_image_blocks(message: discord.Message, budget: int) -> list[dict]:
    """Base64 image blocks for every image the moderation scanner would see on a message —
    attachments, (non-Lottie) stickers, and embedded images / Tenor+Giphy GIFs / links —
    so chat understands the same content types moderation does. Capped by budget."""
    if budget <= 0:
        return []
    sources: list[tuple[bytes, str]] = []
    for _, mime, raw in await _sticker_attachment_payloads(message):  # attachments + stickers
        sources.append((raw, mime))
    for _, url in _embed_image_urls(message):  # embed images, GIF previews, image links
        raw = await _fetch_image_bytes(url)
        if raw:
            sources.append((raw, "image/png"))
    blocks: list[dict] = []
    for raw, mime in sources:
        if budget <= 0:
            break
        b = await asyncio.to_thread(_raw_to_image_block, raw, mime)
        if b is not None:
            blocks.append(b)
            budget -= 1
    return blocks


def _has_media(m: discord.Message) -> bool:
    return bool(m.attachments or m.stickers or _embed_image_urls(m))


def _clean_content(m: discord.Message, note_image: bool = False) -> str:
    """Message text with mentions resolved to names and the bot's own mention stripped.
    Appends '[sent an image]' when note_image is set (image present but not attached)."""
    text = (m.clean_content or "").strip()
    names = {bot.user.display_name, bot.user.name} if bot.user else set()
    if m.guild and m.guild.me:
        names.add(m.guild.me.display_name)
    for name in filter(None, names):
        text = text.replace(f"@{name}", "").strip()
    if note_image:
        text = (text + " [sent an image]").strip()
    return text


async def _build_chat_history(message: discord.Message) -> list[dict]:
    """Walk up the reply chain and return chronological user/assistant turns, each non-bot
    message prefixed with the author's name. Images from the newest messages are attached
    so the bot can actually see pics it was sent/replied to (up to MAX_CHAT_IMAGES)."""
    chain: list[discord.Message] = []
    msg: discord.Message | None = message
    while msg is not None and len(chain) < CHAT_CHAIN_LIMIT:
        chain.append(msg)
        ref = msg.reference
        nxt = None
        if ref is not None:
            if isinstance(ref.resolved, discord.Message):
                nxt = ref.resolved
            elif ref.message_id:
                try:
                    nxt = await msg.channel.fetch_message(ref.message_id)
                except discord.HTTPException:
                    nxt = None
        msg = nxt
    chain.reverse()  # oldest -> newest

    self_id = bot.user.id if bot.user else None
    # Attach real images from the newest messages first, up to the budget.
    img_blocks: dict[int, list[dict]] = {}
    budget = MAX_CHAT_IMAGES
    for m in reversed(chain):
        if budget <= 0:
            break
        if m.author.id == self_id or not _has_media(m):
            continue
        blocks = await _message_image_blocks(m, budget)
        if blocks:
            img_blocks[m.id] = blocks
            budget -= len(blocks)

    history: list[dict] = []
    for m in chain:
        imgs = img_blocks.get(m.id, [])
        # note "[sent an image]" only when media was present but we didn't attach it
        text = _clean_content(m, note_image=_has_media(m) and not imgs)
        if not text and not imgs:
            continue
        if m.author.id == self_id:
            history.append({"role": "assistant", "content": text or "..."})
        elif imgs:
            label = f"{m.author.display_name}: {text}".strip()
            history.append({"role": "user", "content": imgs + [{"type": "text", "text": label}]})
        else:
            history.append({"role": "user", "content": f"{m.author.display_name}: {text}"})
    while history and history[0]["role"] == "assistant":  # must start with a user turn
        history.pop(0)
    return history


async def _chat_reply(message: discord.Message) -> None:
    now = time.monotonic()
    if now - _ask_last.get(message.author.id, 0.0) < ASK_COOLDOWN:
        return  # rate-limit silently
    _ask_last[message.author.id] = now
    try:
        history = await _build_chat_history(message)
    except Exception:
        log.exception("building chat history failed")
        return
    if not history:
        return

    max_tokens, guidance = ASK_LENGTHS["short"]  # chat stays snappy
    system = ASK_SYSTEM_BASE + (ASK_SEARCH_HINT if ASK_WEB_SEARCH else "") + " " + guidance
    kwargs: dict = {"model": ASK_MODEL, "max_tokens": max_tokens, "system": system}
    if ASK_WEB_SEARCH:
        kwargs["tools"] = ASK_TOOLS
    try:
        async with message.channel.typing():
            msgs = history
            resp = None
            for _ in range(3):  # resume across any web-search pause
                async with check_semaphore:
                    resp = await claude.messages.create(messages=msgs, **kwargs)
                if resp.stop_reason != "pause_turn":
                    break
                msgs = msgs + [{"role": "assistant", "content": resp.content}]
            answer = _extract_answer(resp)
    except Exception:
        log.exception("chat reply failed")
        return
    if not answer:
        return
    if len(answer) > 1990:
        answer = answer[:1987] + "…"
    try:
        await message.reply(
            answer, mention_author=False,
            allowed_mentions=discord.AllowedMentions.none(),
        )
    except discord.HTTPException:
        log.warning("could not send chat reply in #%s", message.channel)


def _extract_answer(resp) -> str:
    """The final answer text — text after the last tool activity, so a 'let me search'
    preamble is dropped. Falls back to all text if there was no tool use."""
    blocks = list(resp.content)
    last_tool = -1
    for i, b in enumerate(blocks):
        t = getattr(b, "type", "")
        if t == "server_tool_use" or "tool_result" in t:
            last_tool = i
    tail = blocks[last_tool + 1:] if last_tool >= 0 else blocks
    text = "".join(b.text for b in tail if getattr(b, "type", "") == "text").strip()
    if not text:
        text = "".join(b.text for b in blocks if getattr(b, "type", "") == "text").strip()
    # Guarantee no em dashes regardless of what the model produced.
    text = re.sub(r"\s*—\s*", ", ", text)
    return text


@bot.tree.command(name="ask", description="Ask a question and get an answer")
@app_commands.guild_only()
@app_commands.describe(
    question="What do you want to ask?",
    length="How long the answer should be (default: short)",
    visibility="Post the answer for everyone (default), or show it only to you",
)
@app_commands.choices(
    length=[
        app_commands.Choice(name="short — 1-2 sentences", value="short"),
        app_commands.Choice(name="medium — a short paragraph", value="medium"),
        app_commands.Choice(name="long — detailed", value="long"),
    ],
    visibility=[
        app_commands.Choice(name="post — everyone can see it (default)", value="public"),
        app_commands.Choice(name="private — only you can see it", value="private"),
    ],
)
async def ask_cmd(
    interaction: discord.Interaction,
    question: str,
    length: app_commands.Choice[str] | None = None,
    visibility: app_commands.Choice[str] | None = None,
):
    q = (question or "").strip()[:1000]
    if not q:
        await interaction.response.send_message("Say something first.", ephemeral=True)
        return
    wait = ASK_COOLDOWN - (time.monotonic() - _ask_last.get(interaction.user.id, 0.0))
    if wait > 0:
        await interaction.response.send_message(
            f"Please wait {wait:.0f}s before asking again.", ephemeral=True
        )
        return
    _ask_last[interaction.user.id] = time.monotonic()

    private = bool(visibility) and visibility.value == "private"  # default: public
    max_tokens, guidance = ASK_LENGTHS[length.value if length else "short"]
    system = ASK_SYSTEM_BASE + (ASK_SEARCH_HINT if ASK_WEB_SEARCH else "") + " " + guidance
    kwargs: dict = {"model": ASK_MODEL, "max_tokens": max_tokens, "system": system}
    if ASK_WEB_SEARCH:
        kwargs["tools"] = ASK_TOOLS

    await interaction.response.defer(ephemeral=private, thinking=True)
    try:
        messages = [{"role": "user", "content": q}]
        resp = None
        for _ in range(3):  # a web search may pause the turn; resume until it's done
            async with check_semaphore:  # shares the rate-limit budget with scanning
                resp = await claude.messages.create(messages=messages, **kwargs)
            if resp.stop_reason != "pause_turn":
                break
            messages.append({"role": "assistant", "content": resp.content})
        answer = _extract_answer(resp)
    except Exception:
        log.exception("/ask failed")
        await interaction.followup.send(
            "Sorry — I couldn't answer that right now.", ephemeral=True
        )
        return

    answer = answer or "..."
    header = f"**You:** {q}" if private else f"{interaction.user.mention}: {q}"
    out = f"{header}\n\n{answer}"
    if len(out) > 1990:  # Discord's 2000-char message limit
        out = out[:1987] + "…"
    await interaction.followup.send(
        out, ephemeral=private, allowed_mentions=discord.AllowedMentions.none()
    )


@mod.command(name="status", description="Show current configuration")
async def status_cmd(interaction: discord.Interaction):
    cfg = state.guild(interaction.guild.id)
    review = cfg["review_channel"]
    exempt = cfg["exempt_channels"]
    premium = _premium(interaction.guild.id)
    embed = discord.Embed(title="Sentry status", colour=discord.Colour.blurple())
    embed.add_field(
        name="Tier",
        value="✅ premium"
        if premium
        else f"free (watch-only, {FREE_SCAN_LIMIT} scans/day)",
    )
    embed.add_field(name="Scanning", value="on" if cfg["enabled"] else "off")
    embed.add_field(
        name="Mode",
        value="🟡 dry run (no action)"
        if _effective_dry(interaction.guild.id, cfg)
        else "enforcing",
    )
    today = discord.utils.utcnow().date().isoformat()
    used = cfg.get("scan_count", 0) if cfg.get("scan_day") == today else 0
    embed.add_field(
        name="Scans today", value=f"{used}" if premium else f"{used}/{FREE_SCAN_LIMIT}"
    )
    embed.add_field(name="Sensitivity", value=cfg["sensitivity"])
    embed.add_field(name="Model", value=MODEL, inline=False)
    embed.add_field(
        name="Review channel",
        value=f"<#{review}>" if review else "**not set** — run `/sentry setup`",
        inline=False,
    )
    embed.add_field(
        name="Excluded channels",
        value=", ".join(f"<#{c}>" for c in exempt) if exempt else "none",
        inline=False,
    )
    min_conf = cfg.get("min_confidence", DEFAULT_MIN_CONFIDENCE)
    level_name = next(
        (k for k, v in CONFIDENCE_LEVELS.items() if abs(v - min_conf) < 1e-9),
        f"{min_conf:.2f}",
    )
    embed.add_field(
        name="Quarantine threshold", value=f"{level_name} (≥ {min_conf:.2f})", inline=True
    )
    embed.add_field(name="Downscale", value=f"{MAX_EDGE}px long edge", inline=True)
    embed.add_field(
        name="Remembered",
        value=f"{len(cfg.get('approved_hashes', []))} approved · "
        f"{len(cfg.get('blocked_hashes', {}))} blocked",
        inline=True,
    )
    disabled = cfg.get("disabled_categories", [])
    embed.add_field(
        name="Disabled categories",
        value=", ".join(disabled) if disabled else "none (all on)",
        inline=False,
    )
    missing = _missing_perms(interaction.guild)
    embed.add_field(
        name="Permissions",
        value="✅ all present"
        if not missing
        else "⚠️ **missing:** " + ", ".join(missing),
        inline=False,
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(
    name="post",
    description="Upload an image through moderation with zero public exposure",
)
@app_commands.describe(image="Image to post", text="Optional message to go with it")
async def post_cmd(
    interaction: discord.Interaction,
    image: discord.Attachment,
    text: str | None = None,
):
    """True pre-publish gate: nothing is visible to anyone until Claude approves.

    The bot posts the image itself, credited to the uploader.
    """
    await interaction.response.defer(ephemeral=True, thinking=True)

    if not (image.content_type or "").startswith("image/"):
        await interaction.followup.send("That is not an image.", ephemeral=True)
        return

    cfg = state.guild(interaction.guild.id)
    raw = await image.read()

    # Staff (anyone who can see the review channel) are exempt — post without scanning.
    if cfg.get("exempt_reviewers", True) and _is_reviewer(
        interaction.guild, interaction.user, cfg
    ):
        body = f"{interaction.user.mention}:" + (f" {text}" if text else "")
        await interaction.channel.send(
            content=body,
            file=discord.File(io.BytesIO(raw), filename=image.filename),
            allowed_mentions=discord.AllowedMentions(everyone=False, roles=False, users=False),
        )
        await interaction.followup.send("Posted (staff — not scanned).", ephemeral=True)
        return

    verdict = await classify(
        raw,
        image.content_type or "image/png",
        cfg.get("sensitivity", "standard"),
        _allowances_text(cfg),
    )

    min_conf = cfg.get("min_confidence", DEFAULT_MIN_CONFIDENCE)
    disabled = _effective_disabled(interaction.guild.id, cfg)
    if _should_quarantine(verdict, min_conf, disabled):
        restricted = await restrict(
            interaction.user, f"flagged via /post: {verdict.get('category')}"
        )
        await interaction.followup.send(
            f"Withheld — flagged as `{verdict.get('category')}`. "
            + (
                "Your image permissions are suspended pending admin review."
                if restricted
                else "Nothing was posted."
            ),
            ephemeral=True,
        )
        fake = type("_M", (), {})()  # minimal shim for open_case
        fake.guild = interaction.guild
        fake.channel = interaction.channel
        fake.author = interaction.user
        fake.content = text or ""
        await open_case(
            fake,
            [(image.filename, raw, verdict)],
            verdict,
            restricted,
        )
        return

    body = f"{interaction.user.mention}:" + (f" {text}" if text else "")
    await interaction.channel.send(
        content=body,
        file=discord.File(io.BytesIO(raw), filename=image.filename),
        allowed_mentions=discord.AllowedMentions(everyone=False, roles=False, users=False),
    )
    await interaction.followup.send("Approved and posted.", ephemeral=True)


# --- /sentry allow: per-server exceptions injected into the classifier prompt ---
allow = app_commands.Group(
    name="allow",
    description="Community-specific exceptions Sentry should not flag",
    parent=mod,
)


@allow.command(
    name="add", description="Permit something Sentry would otherwise flag (e.g. reclaimed slur)"
)
@app_commands.describe(rule="Describe what to allow, in plain words")
async def allow_add(interaction: discord.Interaction, rule: str):
    cfg = state.guild(interaction.guild.id)
    rule = rule.strip()[:200]
    if not rule:
        await interaction.response.send_message("Nothing to add.", ephemeral=True)
        return
    rules = cfg.setdefault("allowances", [])
    if len(rules) >= ALLOWANCE_MAX:
        await interaction.response.send_message(
            f"At the limit of {ALLOWANCE_MAX} allowances — remove one first.", ephemeral=True
        )
        return
    if rule in rules:
        await interaction.response.send_message("That allowance already exists.", ephemeral=True)
        return
    rules.append(rule)
    state.save()
    await interaction.response.send_message(
        f"Added allowance #{len(rules)}: `{rule}`.\nSentry will no longer flag an image "
        "whose only issue is this. It never excuses anything else.",
        ephemeral=True,
    )


@allow.command(name="list", description="Show this server's allowances")
async def allow_list(interaction: discord.Interaction):
    rules = state.guild(interaction.guild.id).get("allowances", [])
    if not rules:
        await interaction.response.send_message(
            "No allowances set. Add one with `/sentry allow add`.", ephemeral=True
        )
        return
    body = "\n".join(f"{i}. {r}" for i, r in enumerate(rules, 1))
    await interaction.response.send_message(
        f"**Allowances for this server:**\n{body}", ephemeral=True
    )


@allow.command(
    name="remove", description="Remove an allowance by its number (see /sentry allow list)"
)
@app_commands.describe(number="The number shown by /sentry allow list")
async def allow_remove(interaction: discord.Interaction, number: int):
    cfg = state.guild(interaction.guild.id)
    rules = cfg.get("allowances", [])
    if not 1 <= number <= len(rules):
        await interaction.response.send_message(
            f"No allowance #{number}. Check `/sentry allow list`.", ephemeral=True
        )
        return
    removed = rules.pop(number - 1)
    state.save()
    await interaction.response.send_message(f"Removed: `{removed}`.", ephemeral=True)


@allow.command(name="clear", description="Remove all allowances for this server")
async def allow_clear(interaction: discord.Interaction):
    state.guild(interaction.guild.id)["allowances"] = []
    state.save()
    await interaction.response.send_message("All allowances cleared.", ephemeral=True)


bot.tree.add_command(mod)


# --------------------------------------------------------------------------
# Admin dashboard — a tiny web UI for the bot owner to manage the allowlist.
# Disabled unless SENTRY_ADMIN_TOKEN is set. Binds to 127.0.0.1 by default so it's
# only reachable over an SSH tunnel; set SENTRY_ADMIN_BIND=0.0.0.0:PORT to expose it.
# --------------------------------------------------------------------------

ADMIN_TOKEN = os.getenv("SENTRY_ADMIN_TOKEN", "")
ADMIN_BIND = os.getenv("SENTRY_ADMIN_BIND", "127.0.0.1:8899")
_admin_runner: "web.AppRunner | None" = None


def _admin_authed(request: "web.Request") -> bool:
    if not ADMIN_TOKEN:
        return False
    supplied = request.query.get("token") or request.headers.get("X-Admin-Token", "")
    return hmac.compare_digest(supplied, ADMIN_TOKEN)


_ADMIN_STYLE = """<style>
body{font:15px system-ui;margin:2rem;max-width:820px;color:#111}
a{color:#2b6cb0}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ccc;padding:6px 10px;text-align:left}
button{cursor:pointer;padding:4px 10px}code{font-size:13px}
fieldset{border:1px solid #ccc;border-radius:6px;margin:1rem 0;padding:.6rem 1rem}
legend{font-weight:600;padding:0 .4rem}label{display:block;margin:.35rem 0}
input[type=text],select{padding:3px 6px;min-width:16rem}
textarea{width:100%;box-sizing:border-box;padding:6px;font:inherit}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:.2rem 1.5rem}
.note{color:#666;font-size:13px}.warn{color:#b45309}</style>"""


def _premium_form(token: str, gid: int) -> str:
    if state.is_env_allowed(gid):
        return "<em>via SENTRY_ALLOWLIST</em>"
    nxt = "remove" if state.is_state_allowed(gid) else "add"
    label = "Revoke premium" if nxt == "remove" else "Grant premium"
    return (
        f"<form method=post action='/set?token={_esc(token)}' style='display:inline'>"
        f"<input type=hidden name=guild_id value='{gid}'>"
        f"<input type=hidden name=action value='{nxt}'>"
        f"<button>{label}</button></form>"
    )


def _today() -> str:
    return discord.utils.utcnow().date().isoformat()


def _config_issues(gid: int, cfg: dict) -> list[str]:
    """Human-readable misconfigurations that would silently break moderation."""
    issues = []
    if cfg.get("enabled", True) and not cfg.get("review_channel"):
        issues.append("no review channel set — flagged cases can't be posted")
    if (
        state.is_allowed(gid)
        and not cfg.get("dry_run", DEFAULT_DRY_RUN)
        and not cfg.get("restricted_role")
    ):
        issues.append("no restricted role — offenders are deleted but not restricted")
    return issues


def _read_audit(limit: int = 50, guild_id: int | None = None) -> list[dict]:
    """Most-recent-first audit records from the current log file. Best-effort."""
    try:
        lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for ln in reversed(lines):
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if guild_id is not None and str(rec.get("guild")) != str(guild_id):
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out


def _audit_table(records: list[dict], show_guild: bool = False) -> str:
    if not records:
        return "<p class=note>No recorded activity yet.</p>"
    head = "<tr><th>Time (UTC)</th><th>Event</th>"
    if show_guild:
        head += "<th>Guild</th>"
    head += "<th>Category</th><th>Conf.</th><th>Reason</th><th>User</th></tr>"
    body = ""
    for r in records:
        ts = _esc(str(r.get("ts", ""))[:19].replace("T", " "))
        conf = r.get("confidence")
        conf = f"{conf:.2f}" if isinstance(conf, (int, float)) else "—"
        reason = _esc(str(r.get("reason") or ""))[:60]
        user = r.get("user") or r.get("actor") or "—"
        body += f"<tr><td>{ts}</td><td>{_esc(str(r.get('event','')))}</td>"
        if show_guild:
            body += f"<td><code>{_esc(str(r.get('guild', '—')))}</code></td>"
        body += (
            f"<td>{_esc(str(r.get('category') or '—'))}</td><td>{conf}</td>"
            f"<td>{reason}</td><td><code>{_esc(str(user))}</code></td></tr>"
        )
    return f"<table>{head}{body}</table>"


def _admin_page(token: str) -> str:
    in_guild = {g.id: g for g in bot.guilds}
    today = _today()
    n_premium = sum(1 for g in bot.guilds if state.is_allowed(g.id))
    scans_today = sum(
        cfg.get("scan_count", 0)
        for g in bot.guilds
        if (cfg := state.guild(g.id)).get("scan_day") == today
    )
    n_issues = sum(1 for g in bot.guilds if _config_issues(g.id, state.guild(g.id)))
    summary = (
        f"<p><b>{len(bot.guilds)}</b> servers · <b>{n_premium}</b> premium · "
        f"<b>{scans_today}</b> scans today · "
        + (
            f"<span class=warn><b>{n_issues}</b> with config issues</span>"
            if n_issues
            else "no config issues"
        )
        + f" · <a href='/activity?token={_esc(token)}'>recent activity →</a></p>"
    )

    def settings_link(gid: int) -> str:
        return f"<a href='/guild?id={gid}&token={_esc(token)}'>Settings</a>"

    rows = ""
    for g in sorted(bot.guilds, key=lambda x: (x.name or "").lower()):
        badge = "✅ premium" if state.is_allowed(g.id) else "free"
        issues = _config_issues(g.id, state.guild(g.id))
        health = (
            f"<span class=warn title='{_esc('; '.join(issues))}'>⚠️ {len(issues)}</span>"
            if issues
            else "✓"
        )
        rows += (
            f"<tr><td>{_esc(g.name)}</td><td><code>{g.id}</code></td>"
            f"<td>{g.member_count or '?'}</td><td>{badge}</td><td>{health}</td>"
            f"<td>{_premium_form(token, g.id)}</td><td>{settings_link(g.id)}</td></tr>"
        )
    # allowlisted ids the bot isn't currently in
    extra = ""
    for gid in state.allowlist():
        if int(gid) not in in_guild:
            extra += (
                f"<tr><td><em>not joined</em></td><td><code>{_esc(gid)}</code></td>"
                f"<td>—</td><td>✅ premium</td><td>—</td>"
                f"<td>{_premium_form(token, int(gid))}</td>"
                f"<td>{settings_link(int(gid))}</td></tr>"
            )
    return f"""<!doctype html><meta charset=utf-8>
<title>Sentry admin</title>{_ADMIN_STYLE}
<h2>Sentry — servers</h2>
{summary}
<p>Grant premium (all categories + enforcement) or open <b>Settings</b> to change any
per-server knob.</p>
<table><tr><th>Server</th><th>ID</th><th>Members</th><th>Tier</th><th>Health</th>
<th>Premium</th><th>Config</th></tr>
{rows}{extra}</table>
<h3>Add a server by ID</h3>
<form method=post action='/set?token={_esc(token)}'>
<input type=text name=guild_id placeholder='server id' required>
<input type=hidden name=action value='add'>
<button>Grant premium</button></form>"""


def _guild_settings_page(token: str, gid: int) -> str:
    cfg = state.guild(gid)
    g = bot.get_guild(gid)
    name = _esc(g.name) if g else "<em>not joined</em>"
    premium = state.is_allowed(gid)

    def checked(cond: bool) -> str:
        return " checked" if cond else ""

    def sel(values, current) -> str:
        return "".join(
            f"<option value='{v}'{' selected' if v == current else ''}>{v}</option>"
            for v in values
        )

    disabled = set(cfg.get("disabled_categories", []))
    cat_boxes = "".join(
        f"<label><input type=checkbox name='cat_{c}'{checked(c not in disabled)}> {c}</label>"
        for c in CATEGORIES
    )
    min_conf = cfg.get("min_confidence", DEFAULT_MIN_CONFIDENCE)
    level = next(
        (k for k, v in CONFIDENCE_LEVELS.items() if abs(v - min_conf) < 1e-9), "medium"
    )
    exempt = ", ".join(str(c) for c in cfg.get("exempt_channels", []))
    free_note = (
        ""
        if premium
        else "<p class=warn>This server is <b>free</b> — it stays watch-only "
        "(nothing is removed) and capped regardless of the Mode/category settings "
        "below. Grant premium to make enforcement take effect.</p>"
    )

    def val(key):
        v = cfg.get(key)
        return "" if v is None else str(v)

    issues = _config_issues(gid, cfg)
    issues_html = (
        "<p class=warn><b>⚠️ Config issues:</b><br>"
        + "<br>".join(_esc(i) for i in issues)
        + "</p>"
        if issues
        else ""
    )
    used = cfg.get("scan_count", 0) if cfg.get("scan_day") == _today() else 0
    allow_text = _esc("\n".join(cfg.get("allowances", [])))
    activity_html = _audit_table(_read_audit(15, gid))

    return f"""<!doctype html><meta charset=utf-8>
<title>Sentry — {name}</title>{_ADMIN_STYLE}
<p><a href='/?token={_esc(token)}'>← all servers</a></p>
<h2>{name} <code>{gid}</code></h2>
<p>Tier: <b>{'✅ premium' if premium else 'free'}</b> &nbsp; {_premium_form(token, gid)}</p>
{issues_html}{free_note}
<form method=post action='/guild/save?token={_esc(token)}'>
<input type=hidden name=guild_id value='{gid}'>
<fieldset><legend>Behavior</legend>
<label><input type=checkbox name=enabled{checked(cfg.get('enabled', True))}>
  Scanning enabled (server-wide)</label>
<label><input type=checkbox name=enforce{checked(not cfg.get('dry_run', DEFAULT_DRY_RUN))}>
  Enforce — remove flagged images (unchecked = watch-only / dry run)</label>
<label><input type=checkbox name=exempt_reviewers{checked(cfg.get('exempt_reviewers', True))}>
  Staff bypass — don't moderate anyone who can see the review channel (uncheck to test on staff)</label>
<label>Sensitivity (what Claude flags):
  <select name=sensitivity>{sel(SENSITIVITY_LEVELS, cfg.get('sensitivity', 'standard'))}</select></label>
<label>Threshold (confidence to act):
  <select name=threshold>{sel(CONFIDENCE_LEVELS.keys(), level)}</select></label>
</fieldset>
<fieldset><legend>Categories (checked = flagged)</legend>
<div class=grid>{cat_boxes}</div>
</fieldset>
<fieldset><legend>Allowances <span class=note>(one per line, max {ALLOWANCE_MAX})</span></legend>
<p class=note>Community-specific exceptions injected into the classifier — an image is
not flagged if its only issue is listed here (e.g. reclaimed in-group slur use). Never
excuses anything else.</p>
<textarea name=allowances rows=4>{allow_text}</textarea>
</fieldset>
<fieldset><legend>Channel / role bindings <span class=note>(numeric IDs; blank = unset)</span></legend>
<label>Review channel ID:
  <input type=text name=review_channel value='{val('review_channel')}'></label>
<label>Restricted role ID:
  <input type=text name=restricted_role value='{val('restricted_role')}'></label>
<label>Alert role ID (pinged on every removal):
  <input type=text name=alert_role value='{val('alert_role')}'></label>
<label>Excluded channel IDs <span class=note>(comma-separated)</span>:
  <input type=text name=exempt_channels value='{_esc(exempt)}'></label>
</fieldset>
<button>Save settings</button>
</form>
<fieldset><legend>Daily scans</legend>
<p><b>{used}</b> scans today (UTC){'' if premium else f' / {FREE_SCAN_LIMIT} cap'}.
<span class=note>{'Premium — uncapped.' if premium else 'Free tier stops at the cap.'}</span></p>
<form method=post action='/guild/quota-reset?token={_esc(token)}'>
<input type=hidden name=guild_id value='{gid}'>
<button>Reset today's quota</button></form>
</fieldset>
<h3>Recent activity (this server)</h3>
{activity_html}"""


def _parse_id(raw: str):
    raw = (raw or "").strip()
    return int(raw) if raw.isdigit() else None


async def _admin_index(request: "web.Request") -> "web.Response":
    if not _admin_authed(request):
        return web.Response(status=401, text="unauthorized")
    return web.Response(
        text=_admin_page(request.query.get("token", "")), content_type="text/html"
    )


async def _admin_set(request: "web.Request") -> "web.Response":
    if not _admin_authed(request):
        return web.Response(status=401, text="unauthorized")
    data = await request.post()
    gid = str(data.get("guild_id", "")).strip()
    if gid.isdigit():
        state.set_allowed(int(gid), data.get("action") == "add")
    raise web.HTTPFound(f"/?token={request.query.get('token', '')}")


async def _admin_guild(request: "web.Request") -> "web.Response":
    if not _admin_authed(request):
        return web.Response(status=401, text="unauthorized")
    gid = _parse_id(request.query.get("id", ""))
    if gid is None:
        raise web.HTTPFound(f"/?token={request.query.get('token', '')}")
    return web.Response(
        text=_guild_settings_page(request.query.get("token", ""), gid),
        content_type="text/html",
    )


async def _admin_guild_save(request: "web.Request") -> "web.Response":
    if not _admin_authed(request):
        return web.Response(status=401, text="unauthorized")
    token = request.query.get("token", "")
    data = await request.post()
    gid = _parse_id(str(data.get("guild_id", "")))
    if gid is None:
        raise web.HTTPFound(f"/?token={token}")
    cfg = state.guild(gid)
    cfg["enabled"] = "enabled" in data
    cfg["dry_run"] = "enforce" not in data
    cfg["exempt_reviewers"] = "exempt_reviewers" in data
    if data.get("sensitivity") in SENSITIVITY_LEVELS:
        cfg["sensitivity"] = data.get("sensitivity")
    if data.get("threshold") in CONFIDENCE_LEVELS:
        cfg["min_confidence"] = CONFIDENCE_LEVELS[data.get("threshold")]
    cfg["disabled_categories"] = [c for c in CATEGORIES if f"cat_{c}" not in data]
    cfg["review_channel"] = _parse_id(str(data.get("review_channel", "")))
    cfg["restricted_role"] = _parse_id(str(data.get("restricted_role", "")))
    cfg["alert_role"] = _parse_id(str(data.get("alert_role", "")))
    cfg["exempt_channels"] = [
        int(x) for x in re.split(r"[,\s]+", str(data.get("exempt_channels", "")))
        if x.strip().isdigit()
    ]
    cfg["allowances"] = [
        ln.strip()[:200]
        for ln in str(data.get("allowances", "")).splitlines()
        if ln.strip()
    ][:ALLOWANCE_MAX]
    state.save()
    raise web.HTTPFound(f"/guild?id={gid}&token={token}")


async def _admin_quota_reset(request: "web.Request") -> "web.Response":
    if not _admin_authed(request):
        return web.Response(status=401, text="unauthorized")
    token = request.query.get("token", "")
    data = await request.post()
    gid = _parse_id(str(data.get("guild_id", "")))
    if gid is None:
        raise web.HTTPFound(f"/?token={token}")
    cfg = state.guild(gid)
    cfg.update(scan_day=_today(), scan_count=0, quota_notified=False)
    state.save()
    raise web.HTTPFound(f"/guild?id={gid}&token={token}")


async def _admin_activity(request: "web.Request") -> "web.Response":
    if not _admin_authed(request):
        return web.Response(status=401, text="unauthorized")
    token = request.query.get("token", "")
    records = _read_audit(200)
    page = f"""<!doctype html><meta charset=utf-8>
<title>Sentry — activity</title>{_ADMIN_STYLE}
<p><a href='/?token={_esc(token)}'>← all servers</a></p>
<h2>Recent activity (all servers)</h2>
<p class=note>Newest first, from the current audit log ({_esc(AUDIT_LOG_PATH.name)}).</p>
{_audit_table(records, show_guild=True)}"""
    return web.Response(text=page, content_type="text/html")


async def start_admin_dashboard() -> None:
    global _admin_runner
    if not ADMIN_TOKEN:
        log.info("admin dashboard disabled (set SENTRY_ADMIN_TOKEN to enable)")
        return
    app = web.Application()
    app.router.add_get("/", _admin_index)
    app.router.add_post("/set", _admin_set)
    app.router.add_get("/guild", _admin_guild)
    app.router.add_post("/guild/save", _admin_guild_save)
    app.router.add_post("/guild/quota-reset", _admin_quota_reset)
    app.router.add_get("/activity", _admin_activity)
    host, _, port = ADMIN_BIND.partition(":")
    _admin_runner = web.AppRunner(app)
    await _admin_runner.setup()
    await web.TCPSite(_admin_runner, host or "127.0.0.1", int(port or 8899)).start()
    log.info("admin dashboard listening on http://%s", ADMIN_BIND)


async def stop_admin_dashboard() -> None:
    global _admin_runner
    if _admin_runner:
        await _admin_runner.cleanup()
        _admin_runner = None


if __name__ == "__main__":
    try:
        bot.run(DISCORD_TOKEN, log_handler=None)
    finally:
        state.close()  # final flush + close the DB even on abnormal exit
