"""Offline dry run: exercises process() and open_case() with fake Discord
objects and a stubbed Claude, so the logic can be verified without a token."""

import asyncio
import io
import json
import os
from types import SimpleNamespace

os.environ.setdefault("DISCORD_TOKEN", "fake")
os.environ.setdefault("ANTHROPIC_API_KEY", "fake")
os.environ["SENTRY_STATE"] = "/tmp/dryrun_state.json"

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

    async def delete(self):
        self.deleted = True
        EVENTS.append(("delete", [a.filename for a in self.attachments]))


# ------------------------------------------------------------------- harness


async def scenario(label, verdict, attachments, *, raise_error=False):
    EVENTS.clear()
    CALLS.clear()
    sentry.verdict_cache.clear()
    NEXT_VERDICT.clear()
    NEXT_VERDICT.update(payload=verdict, raise_error=raise_error)
    NEXT_VERDICT["raise"] = raise_error

    guild = FakeGuild()
    cfg = sentry.state.guild(guild.id)
    cfg["review_channel"] = 77
    cfg["restricted_role"] = 999

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

    await scenario("clean image passes untouched", clean, [FakeAttachment("cat.png", (90, 160, 90))])
    await scenario("gore flagged", gore, [FakeAttachment("bad.png", (170, 20, 20))])
    await scenario(
        "mixed message, one bad attachment",
        gore,
        [FakeAttachment("a.png", (10, 10, 200)), FakeAttachment("b.png", (200, 10, 10))],
    )
    await scenario("critical category", csam, [FakeAttachment("x.png", (30, 30, 30))])
    await scenario(
        "API outage, FAIL_MODE=closed", clean, [FakeAttachment("y.png", (80, 80, 80))],
        raise_error=True,
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


asyncio.run(main())
