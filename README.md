# Sentry — Claude-backed image moderation for Discord

Watches uploaded images, sends each one to Claude vision, and deletes anything
classified as nudity or gore. The poster loses image permissions and a case lands in
your review channel with approve/uphold buttons.

Clean images are never touched — they keep their real author, replies, reactions and
edit history. Single file, no database, ~800 input tokens per image.

## Setup

1. **Create the bot** at <https://discord.com/developers/applications> → Bot.
   Under *Privileged Gateway Intents*, enable **Message Content Intent**.

2. **Invite it** with these permissions (integer `268560384`):
   Manage Roles · Manage Messages · Send Messages · Attach Files · Embed Links ·
   Read Message History

3. **Position its role above** everyone it will moderate, or it cannot assign the
   restriction role.

4. **Run it:**
   ```bash
   pip install -r requirements.txt
   cp .env.example .env   # fill in DISCORD_TOKEN and ANTHROPIC_API_KEY
   python bot.py
   ```

5. **In Discord:** `/sentry setup channel:#mod-review`

## Commands

| Command | Purpose |
|---|---|
| `/sentry setup` | Choose the review channel (warns if @everyone can read it) |
| `/sentry sensitivity` | `relaxed` / `standard` / `strict` |
| `/sentry exempt` | Toggle scanning off for one channel (NSFW channels, mod-only rooms) |
| `/sentry toggle` | Kill switch for the whole server |
| `/sentry status` | Current config |
| `/sentry restrict` / `unrestrict` | Manual permission control |
| `/post` | Upload with **zero** exposure — see below |

All `/sentry` commands require Manage Server. Review buttons require Manage Messages.

## How detection works

1. `on_message` sees attachments and hands off to a background task — the gateway
   keeps flowing, the message stays up.
2. Bytes are downscaled to 768px and sent to Claude Haiku.
3. Clean → nothing happens at all. No edit, no repost, no trace.
4. Flagged → message deleted, author restricted, case opened, author DM'd.

**The image is visible for the duration of the check**, typically 1–2 seconds. That is
the tradeoff for not reposting. If any exposure is unacceptable:

- Deny **Attach Files** to `@everyone` in the channel.
- Users upload with `/post image:` instead.

Slash command attachments aren't published until the bot responds, so nothing is
visible to anyone until Claude approves. The bot then posts the image itself, credited
to the uploader.

**A Discord message is atomic.** If someone attaches four images and one is flagged,
the whole message goes — there is no API for removing a single attachment from another
user's message. The case embed shows how many files tripped it.

## Restriction mechanic

Discord role permissions are additive — a role cannot deny something another role
grants. So the bot creates a `Media Restricted` role and writes a **channel overwrite**
denying Attach Files + Embed Links in every channel it can manage. That is the only
approach that actually holds. Channels created later need `/sentry restrict` run once
to re-apply.

Restrictions never expire on their own. An admin clears them from the review case or
with `/sentry unrestrict`.

## Review cases

Each case embeds the user, origin channel, category, confidence, and a non-graphic
reason. The flagged images are attached with `SPOILER_` filenames so they stay blurred
until a moderator clicks — this is the only surviving copy once the original is deleted,
so the review channel should be mod-only.

Three buttons: **Restore access**, **Uphold restriction**, and **False positive**, which
restores access and DMs the user that they are free to post the image again.

**Exception:** if Claude classifies something as sexual content involving a minor, the
image is **not** re-uploaded to the review channel. The case carries metadata only, plus
reporting links (Discord T&S, NCMEC). Report the account; do not forward the content.

## Tuning

- **False positives** are the main failure mode, and they now cost a real deletion. The
  prompt explicitly calibrates swimwear, shirtless people, cosplay, game screenshots and
  horror makeup as clean. Start on `standard`; move to `relaxed` if your community posts
  a lot of fighting-game or medical content.
- **`SENTRY_FAIL_MODE=closed`** (default) deletes when the API errors. On a provider
  outage that means every image in the server gets deleted — `open` is the safer default
  for large servers, since a missed image is usually cheaper than mass false deletions.
- **Cost:** one Haiku call per image at ~800 input tokens, ~50 output. Identical
  re-uploads hit an in-memory hash cache and cost nothing. Rates:
  <https://claude.com/pricing>
- **Lower `SENTRY_MAX_EDGE` to 512** to roughly halve tokens and shave latency; obvious
  cases hold up well, borderline cases degrade.
- **Videos are not scanned.** Claude vision takes images only.
- Every member is scanned, including moderators and admins. Note that the
  `Media Restricted` role cannot actually constrain a user with Administrator or
  the server owner — Discord permissions override channel overwrites for them — so
  their flagged images are still deleted and a case still opens, but no restriction
  sticks.

## Operational notes

- State lives in `sentry_state.json`. Back it up; both values are recoverable by
  re-running `/sentry setup`.
- Review buttons are persistent — they keep working after a restart.
- One process, asyncio semaphore capping concurrent API calls at 4. An image-spam raid
  queues rather than fanning out, which lengthens the visibility window under load.
