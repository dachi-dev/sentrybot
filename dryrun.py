"""Offline dry run: exercises process() and open_case() with fake Discord
objects and a stubbed Claude, so the logic can be verified without a token."""

import asyncio
import hashlib
import io
import json
import os
from types import SimpleNamespace

os.environ.setdefault("DISCORD_TOKEN", "fake")
os.environ.setdefault("ANTHROPIC_API_KEY", "fake")
os.environ["SENTRY_STATE"] = "/tmp/dryrun_state.json"
# Start each run from a clean slate so the persisted approve/block caches don't
# leak between runs and make the scenarios non-deterministic.
from pathlib import Path as _Path

_Path("/tmp/dryrun_state.json").unlink(missing_ok=True)

import discord
from PIL import Image

import bot as sentry

# ---------------------------------------------------------------- stub Claude

CALLS = []
NEXT_VERDICT = {}


class FakeMessages:
    async def create(self, **kwargs):
        CALLS.append(kwargs)
        if NEXT_VERDICT.get("raise"):
            raise RuntimeError("simulated API outage")
        body = json.dumps(NEXT_VERDICT["payload"])[1:]  # strip "{" for the prefill
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=body)])


sentry.claude = SimpleNamespace(messages=FakeMessages())

# ------------------------------------------------------------- fake Discord

EVENTS = []


class FakeAttachment:
    def __init__(self, name, colour):
        self.filename = name
        self.content_type = "image/png"
        buf = io.BytesIO()
        Image.new("RGB", (1200, 900), colour).save(buf, format="PNG")
        self._raw = buf.getvalue()

    async def read(self):
        return self._raw


class FakeChannel:
    def __init__(self, cid, name):
        self.id, self.name = cid, name
        self.mention = f"#{name}"

    def __str__(self):
        return self.name

    async def send(self, **kw):
        EVENTS.append(("review_post", kw))


class FakeRole:
    def __init__(self):
        self.id, self.name = 999, "Media Restricted"


class FakeMember:
    def __init__(self, guild):
        self.id, self.guild = 4242, guild
        self.mention, self.display_name = "@spammer", "spammer"
        self.bot = False
        self.display_avatar = SimpleNamespace(url="http://x/a.png")
        self.guild_permissions = discord.Permissions.none()
        self.roles = []

    async def add_roles(self, role, reason=None):
        EVENTS.append(("restrict", role.name, reason))
        self.roles.append(role)

    async def send(self, text):
        EVENTS.append(("dm", text[:70]))


class FakeGuild:
    def __init__(self):
        self.id, self.name = 1, "Test Server"
        self.review = FakeChannel(77, "mod-review")
        self._role = FakeRole()

    def get_role(self, rid):
        return self._role

    def get_channel(self, cid):
        return self.review


class FakeMessage:
    def __init__(self, guild, channel, attachments, content=""):
        self.guild, self.channel = guild, channel
        self.author = FakeMember(guild)
        self.attachments, self.content = attachments, content
        self.deleted = False
        self.id = 555
        self.jump_url = "http://discord/jump/555"

    async def delete(self):
        self.deleted = True
        EVENTS.append(("delete", [a.filename for a in self.attachments]))


# ------------------------------------------------------------------- harness


async def scenario(label, verdict, attachments, *, raise_error=False):
    EVENTS.clear()
    CALLS.clear()
    sentry.verdict_cache.clear()
    NEXT_VERDICT.clear()
    NEXT_VERDICT.update(payload=verdict)
    NEXT_VERDICT["raise"] = raise_error

    guild = FakeGuild()
    cfg = sentry.state.guild(guild.id)
    cfg["review_channel"] = 77
    cfg["restricted_role"] = 999
    cfg["approved_hashes"] = []  # isolate scenarios from the persistent caches
    cfg["blocked_hashes"] = {}

    msg = FakeMessage(guild, FakeChannel(10, "general"), attachments, "look at this")
    await sentry.process(msg, attachments, cfg)

    print(f"\n=== {label} ===")
    print(f"  api calls      : {len(CALLS)}")
    print(f"  message deleted: {msg.deleted}")
    for ev in EVENTS:
        if ev[0] == "review_post":
            kw = ev[1]
            embed = kw["embed"]
            files = [f.filename for f in kw.get("files") or []]
            buttons = len(kw["view"].children) if kw.get("view") else 0
            print(f"  case opened    : {embed.title!r}")
            for f in embed.fields:
                print(f"      {f.name}: {str(f.value)[:60]}")
            print(f"      attachments: {files or 'NONE (withheld)'}  buttons: {buttons}")
        else:
            print(f"  {ev[0]:<15}: {ev[1:]}")


async def main():
    clean = {"verdict": "allow", "category": "clean", "confidence": 0.97, "reason": "ok"}
    gore = {
        "verdict": "block",
        "category": "gore",
        "confidence": 0.93,
        "reason": "graphic real injury",
    }
    csam = {
        "verdict": "block",
        "category": "minor_sexual",
        "confidence": 0.88,
        "reason": "policy violation",
    }
    hate = {
        "verdict": "block",
        "category": "hate_symbol",
        "confidence": 0.9,
        "reason": "extremist hate symbol",
    }

    await scenario("clean image passes untouched", clean, [FakeAttachment("cat.png", (90, 160, 90))])
    await scenario("gore flagged", gore, [FakeAttachment("bad.png", (170, 20, 20))])
    await scenario("hate symbol flagged", hate, [FakeAttachment("flag.png", (30, 30, 30))])
    await scenario(
        "mixed message, one bad attachment",
        gore,
        [FakeAttachment("a.png", (10, 10, 200)), FakeAttachment("b.png", (200, 10, 10))],
    )
    await scenario("critical category", csam, [FakeAttachment("x.png", (30, 30, 30))])
    await scenario(
        "API outage → no action + mod-channel notice", clean,
        [FakeAttachment("y.png", (80, 80, 80))], raise_error=True,
    )

    # cache: same bytes twice should cost one call
    EVENTS.clear()
    CALLS.clear()
    sentry.verdict_cache.clear()
    NEXT_VERDICT.update(payload=clean)
    NEXT_VERDICT["raise"] = False
    att = FakeAttachment("dup.png", (120, 120, 200))
    raw = await att.read()
    for _ in range(3):
        await sentry.classify(raw, "image/png", "standard")
    print(f"\n=== hash cache ===\n  3 identical images -> {len(CALLS)} api call(s)")

    # approved allow-list: a whitelisted image is passed untouched, no API call
    EVENTS.clear()
    CALLS.clear()
    sentry.verdict_cache.clear()
    NEXT_VERDICT.update(payload=gore)  # would be blocked if it were classified
    NEXT_VERDICT["raise"] = False
    guild = FakeGuild()
    cfg = sentry.state.guild(guild.id)
    cfg["review_channel"] = 77
    cfg["restricted_role"] = 999
    att = FakeAttachment("approved.png", (10, 200, 10))
    raw = await att.read()
    cfg["approved_hashes"] = [hashlib.sha256(raw).hexdigest()]
    msg = FakeMessage(guild, FakeChannel(10, "general"), [att], "reposting approved image")
    await sentry.process(msg, [att], cfg)
    print("\n=== approved allow-list (image a mod approved) ===")
    print(f"  api calls (want 0)        : {len(CALLS)}")
    print(f"  message deleted (want No) : {msg.deleted}")

    # disapproved cache: a previously-blocked image is re-blocked WITHOUT Claude
    EVENTS.clear()
    CALLS.clear()
    sentry.verdict_cache.clear()
    NEXT_VERDICT.update(payload=clean)  # Claude would say clean — but cache says block
    NEXT_VERDICT["raise"] = False
    guild = FakeGuild()
    cfg = sentry.state.guild(guild.id)
    cfg["review_channel"] = 77
    cfg["restricted_role"] = 999
    cfg["approved_hashes"] = []
    att = FakeAttachment("bad.png", (200, 10, 10))
    raw = await att.read()
    cfg["blocked_hashes"] = {
        hashlib.sha256(raw).hexdigest(): {
            "category": "gore",
            "confidence": 0.9,
            "reason": "cached",
        }
    }
    msg = FakeMessage(guild, FakeChannel(10, "general"), [att], "reposting disapproved image")
    await sentry.process(msg, [att], cfg)
    print("\n=== disapproved cache (image a mod rejected) ===")
    print(f"  api calls (want 0)         : {len(CALLS)}")
    print(f"  message deleted (want Yes) : {msg.deleted}")

    # a message with BOTH a flagged attachment and a flagged embed opens ONE case,
    # not two (the attachment pass deletes it, so the embed pass must be skipped)
    EVENTS.clear()
    CALLS.clear()
    sentry.verdict_cache.clear()
    sentry.embed_scanned.clear()
    NEXT_VERDICT.update(payload=gore)
    NEXT_VERDICT["raise"] = False
    guild = FakeGuild()
    cfg = sentry.state.guild(guild.id)
    cfg["review_channel"] = 77
    cfg["restricted_role"] = 999
    cfg["approved_hashes"] = []
    cfg["blocked_hashes"] = {}
    att = FakeAttachment("both.png", (150, 20, 20))
    msg = FakeMessage(guild, FakeChannel(10, "general"), [att], "look")
    msg.stickers = []
    msg.embeds = [SimpleNamespace()]  # non-empty so the embed path is considered
    _png = io.BytesIO()
    Image.new("RGB", (48, 48), (9, 9, 9)).save(_png, format="PNG")

    async def _fake_fetch(url):
        return _png.getvalue()

    sentry._embed_image_urls = lambda m: [("embed0.img", "http://x/e.png")]
    sentry._fetch_image_bytes = _fake_fetch
    await sentry._scan_created(msg, cfg)
    cases = sum(1 for e in EVENTS if e[0] == "review_post")
    print("\n=== attachment + embed both flagged ===")
    print(f"  cases opened (want 1): {cases}")

    # confidence threshold: a low-confidence block is NOT quarantined when threshold high
    EVENTS.clear()
    CALLS.clear()
    sentry.verdict_cache.clear()
    low_gore = {"verdict": "block", "category": "gore", "confidence": 0.5, "reason": "maybe"}
    NEXT_VERDICT.update(payload=low_gore)
    NEXT_VERDICT["raise"] = False
    guild = FakeGuild()
    cfg = sentry.state.guild(guild.id)
    cfg["review_channel"] = 77
    cfg["restricted_role"] = 999
    cfg["approved_hashes"] = []
    cfg["blocked_hashes"] = {}
    cfg["min_confidence"] = 0.90  # "high"
    att = FakeAttachment("maybe.png", (100, 100, 20))
    msg = FakeMessage(guild, FakeChannel(10, "general"), [att], "borderline")
    await sentry.process(msg, [att], cfg)
    print("\n=== confidence threshold (block 0.50 vs threshold 0.90) ===")
    print(f"  message deleted (want No): {msg.deleted}")

    # media-type sniff: a GIF forced through the raw fallback is labeled image/gif
    _hp = sentry.HAS_PIL
    sentry.HAS_PIL = False
    gbuf = io.BytesIO()
    gfr = [Image.new("RGB", (10, 10), (i * 30, 0, 0)) for i in range(2)]
    gfr[0].save(gbuf, format="GIF", save_all=True, append_images=gfr[1:])
    frames = sentry._extract_frames(gbuf.getvalue(), "image/png")  # declared png, is gif
    sentry.HAS_PIL = _hp
    print("\n=== media-type sniff (declared png, actual gif) ===")
    print(f"  media_type (want image/gif): {frames[0][1] if frames else 'NONE'}")


asyncio.run(main())
