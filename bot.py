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
import io
import json
import logging
import logging.handlers
import os
import re
from collections import OrderedDict
from pathlib import Path
from typing import Any

import aiohttp
import anthropic
import discord
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

MAX_CONCURRENT_CHECKS = int(os.getenv("SENTRY_CONCURRENCY", "4"))
VERDICT_CACHE_SIZE = 512

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


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------


class State:
    """Tiny JSON-backed per-guild config store."""

    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, dict[str, Any]] = {}
        if path.exists():
            try:
                self.data = json.loads(path.read_text())
            except Exception:
                log.exception("state file unreadable, starting fresh")

    def guild(self, guild_id: int) -> dict[str, Any]:
        return self.data.setdefault(
            str(guild_id),
            {
                "review_channel": None,
                "restricted_role": None,
                "enabled": True,
                "sensitivity": "standard",  # relaxed | standard | strict
                "exempt_channels": [],
                "approved_hashes": [],  # sha256s a mod approved; never re-flagged
                "blocked_hashes": {},  # sha256 -> verdict; reposts skip Claude
                "approved_posts": {},  # sha256 -> [[channel_id, message_id]] reposts
                "min_confidence": DEFAULT_MIN_CONFIDENCE,  # quarantine threshold
            },
        )

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2))
        tmp.replace(self.path)


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
- "minor_sexual": any sexualized depiction of a person who appears to be a minor. \
This overrides every other category.
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

Respond with exactly this JSON shape and nothing else:
{{"verdict": "allow" | "block", "category": "clean" | "sexual_nudity" | "gore" | "minor_sexual" | "hate_symbol" | "violence_threat" | "harassment_doxxing" | "self_harm" | "drugs" | "scam_spam", "confidence": 0.0-1.0, "reason": "<max 12 words, non-graphic>"}}"""


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


_RETRYABLE_STATUS = {429, 500, 502, 503, 504, 529}


async def _classify_one(data: str, media_type: str, sensitivity: str) -> dict:
    """One Claude vision call on one prepared frame, retrying transient failures with
    backoff. Never raises; fails open (verdict=allow, error=True) once it gives up."""
    for attempt in range(3):
        try:
            async with check_semaphore:
                resp = await claude.messages.create(
                    model=MODEL,
                    max_tokens=150,
                    system=SYSTEM_PROMPT.format(sensitivity=sensitivity),
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
            if not retryable:
                log.warning("classification rejected (%s): %s", e.status_code, e)
        except Exception:
            log.exception("classification failed")
            retryable = False
        if not retryable or attempt == 2:
            break
        await asyncio.sleep(2**attempt)  # 1s, 2s

    return {
        "verdict": "allow",  # fail open: a failed check never takes action
        "category": "check_failed",
        "confidence": 0.0,
        "reason": "moderation check errored",
        "error": True,
    }


async def classify(raw: bytes, mime: str, sensitivity: str) -> dict:
    """Return a verdict dict for an image. Never raises. For an animation, frames are
    checked in order and the first blocked frame condemns the whole thing."""
    digest = hashlib.sha256(raw).hexdigest()
    cache_key = f"{digest}:{sensitivity}"
    if cached := _cache_get(cache_key):
        return cached

    frames = _extract_frames(raw, mime)
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
        verdict = await _classify_one(data, media_type, sensitivity)
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
        await self.tree.sync()

    async def close(self):
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
        if raw and _looks_like_image(raw):
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


@bot.event
async def on_ready():
    log.info("connected as %s (%d guilds)", bot.user, len(bot.guilds))
    for guild in bot.guilds:
        missing = _missing_perms(guild)
        if missing:
            log.warning("guild '%s' missing permissions: %s", guild.name, ", ".join(missing))


@bot.event
async def on_guild_join(guild: discord.Guild):
    missing = _missing_perms(guild)
    if missing:
        log.warning("joined '%s' missing permissions: %s", guild.name, ", ".join(missing))
    else:
        log.info("joined '%s' with all required permissions", guild.name)


def _guild_scans(message: discord.Message, cfg: dict) -> bool:
    """Shared gate: is this a message in a scanned channel of an enabled guild?"""
    if message.author.bot or message.guild is None:
        return False
    if not cfg["enabled"] or message.channel.id in cfg["exempt_channels"]:
        return False
    if message.channel.id == cfg.get("review_channel"):
        return False
    return True


@bot.event
async def on_message(message: discord.Message):
    if message.guild is None:
        return
    cfg = state.guild(message.guild.id)
    if not _guild_scans(message, cfg):
        return
    # Attachments and stickers are here now; link/GIF embeds usually arrive a moment
    # later via a message edit (handled in on_message_edit).
    if message.attachments or message.stickers or message.embeds:
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
        if raw and _looks_like_image(raw):
            payloads.append((name, "image/png", raw))
    await _run_moderation(message, payloads, cfg)


def _should_quarantine(verdict: dict, min_conf: float) -> bool:
    """Whether a verdict warrants removing the image: a failed check never acts,
    suspected CSAM always acts, otherwise the confidence must clear the threshold."""
    if verdict.get("verdict") != "block" or verdict.get("error"):
        return False
    if verdict.get("category") == "minor_sexual":
        return True
    try:
        confidence = float(verdict.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0.0
    return confidence >= min_conf


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

    # A moderator's decisions are remembered so reposts never hit Claude again:
    # approved images pass untouched; disapproved ones re-block straight from cache.
    approved = set(cfg.get("approved_hashes", []))
    blocked = cfg.get("blocked_hashes", {})

    async def verdict_for(mime: str, raw: bytes) -> dict:
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
        return await classify(raw, mime, sensitivity)

    results = await asyncio.gather(
        *(verdict_for(mime, raw) for _, mime, raw in payloads)
    )

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

    # Quarantine a block only if it's confident enough (a failed check never acts,
    # suspected CSAM always does — see _should_quarantine).
    min_conf = cfg.get("min_confidence", DEFAULT_MIN_CONFIDENCE)
    flagged = [
        (name, raw, v)
        for (name, _, raw), v in zip(payloads, results)
        if _should_quarantine(v, min_conf)
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

    # A message is atomic — one bad item takes the whole message with it.
    try:
        await message.delete()
    except discord.Forbidden:
        log.warning("cannot delete in #%s — missing Manage Messages", channel)
    except discord.NotFound:
        pass  # already gone; still restrict and open the case

    worst = max(flagged, key=lambda f: f[2].get("confidence", 0))[2]
    critical = any(f[2].get("category") == "minor_sexual" for f in flagged)
    restricted = await restrict(author, f"flagged: {worst.get('category')}")

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

    await open_case(message, flagged, worst, restricted, critical)
    return True


async def open_case(
    message: discord.Message,
    flagged: list,
    worst: dict,
    restricted: bool,
    critical: bool,
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
        title="Image removed" + (" — CRITICAL" if critical else ""),
        colour=discord.Colour.red() if not critical else discord.Colour.dark_purple(),
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
            blocked[digest] = {
                "category": v.get("category"),
                "confidence": v.get("confidence", 0.0),
                "reason": v.get("reason", ""),
            }
            changed = True
    if len(blocked) > 10000:  # keep the state file bounded
        for old in list(blocked)[: len(blocked) - 10000]:
            del blocked[old]
        changed = True
    if changed:
        state.save()

    files = []
    if critical:
        # Never re-upload suspected CSAM. Escalate without redistributing.
        embed.description = (
            "**The image was not attached to this case.** Suspected sexual content "
            "involving a minor. Do not attempt to retrieve it. Report the user to "
            "Discord Trust & Safety immediately: <https://dis.gd/report>. In the US, "
            "reports also go to NCMEC CyberTipline: <https://report.cybertip.org>."
        )
    else:
        # Fingerprint the attached images so an approval can be undone later without
        # the bot needing to keep the image around after the case is resolved.
        fps = [hashlib.sha256(raw).hexdigest() for _, raw, _ in flagged[:5]]
        embed.add_field(name="Fingerprint", value=" ".join(fps), inline=False)
        embed.set_footer(
            text="Attachments are spoilered and removed once the case is resolved."
        )
        for name, raw, _ in flagged[:5]:
            files.append(discord.File(io.BytesIO(raw), filename=f"SPOILER_{name}"))

    try:
        await review.send(
            embed=embed,
            files=files,
            view=None if critical else ReviewView(),
            allowed_mentions=discord.AllowedMentions.none(),
        )
    except discord.Forbidden:
        log.warning("cannot post to review channel")


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
        f"(confidence ≥ {CONFIDENCE_LEVELS[level.value]:.2f}). "
        f"Suspected CSAM is always removed regardless.",
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


@mod.command(name="status", description="Show current configuration")
async def status_cmd(interaction: discord.Interaction):
    cfg = state.guild(interaction.guild.id)
    review = cfg["review_channel"]
    exempt = cfg["exempt_channels"]
    embed = discord.Embed(title="Sentry status", colour=discord.Colour.blurple())
    embed.add_field(name="Scanning", value="on" if cfg["enabled"] else "off")
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
    verdict = await classify(
        raw, image.content_type or "image/png", cfg.get("sensitivity", "standard")
    )

    min_conf = cfg.get("min_confidence", DEFAULT_MIN_CONFIDENCE)
    if _should_quarantine(verdict, min_conf):
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
            verdict.get("category") == "minor_sexual",
        )
        return

    body = f"{interaction.user.mention}:" + (f" {text}" if text else "")
    await interaction.channel.send(
        content=body,
        file=discord.File(io.BytesIO(raw), filename=image.filename),
        allowed_mentions=discord.AllowedMentions(everyone=False, roles=False, users=False),
    )
    await interaction.followup.send("Approved and posted.", ephemeral=True)


bot.tree.add_command(mod)


if __name__ == "__main__":
    bot.run(DISCORD_TOKEN, log_handler=None)
