# Sentry — Claude-backed image moderation for Discord

Watches uploaded images, sends each one to Claude vision, and deletes anything that
doesn't belong on a general-audience server — nudity, gore, hate symbols, credible
threats, doxxing, self-harm, hard drugs, and scam/spam. The poster loses image
permissions and a case lands in your review channel with approve/uphold buttons.

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
| `/sentry sensitivity` | `relaxed` / `standard` / `strict` (what Claude flags) |
| `/sentry threshold` | `low` / `medium` / `high` — confidence needed to quarantine |
| `/sentry category` | Turn a category on/off (e.g. disable `harassment_doxxing`) |
| `/sentry dryrun` | Observe-only mode: report flags to the review channel, remove nothing |
| `/sentry alertrole` | Role to ping on **every removal** |
| `/sentry allowlist` | **(bot owner only)** grant/revoke a server's premium access by ID |
| `/sentry exclude` | Exclude a channel from scanning, or re-include it (NSFW channels, mod-only rooms) |
| `/sentry toggle` | Kill switch for the whole server |
| `/sentry status` | Current config |
| `/sentry restrict` / `unrestrict` | Manual permission control |
| `/post` | Upload with **zero** exposure — see below |

All `/sentry` commands require Manage Server. Review buttons require Manage Messages.

## How detection works

1. A message's images are collected and handed to a background task — the gateway
   keeps flowing, the message stays up. Covered sources:
   - **Uploaded image files** (`on_message`).
   - **Stickers** (non-Lottie), fetched and scanned (`on_message`).
   - **Direct image links, and Tenor/Giphy GIFs** — Discord attaches these as *embeds*
     a moment after posting, so they're caught on `on_message_edit`. Article/website/
     YouTube link previews are intentionally skipped.
2. Each image is downscaled to 768px and sent to Claude Haiku. **Animated GIF/WebP are
   sampled across up to `SENTRY_GIF_FRAMES` (default 4) frames** — a clip that's clean on
   frame one but not later doesn't slip through; the first blocked frame condemns it.
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

## Categories

Every category can be turned on/off per server with `/sentry category` and is
subject to the confidence threshold.

| Category | Configurable | Flags |
|---|---|---|
| `sexual_nudity` | yes | explicit nudity / sexual content |
| `gore` | yes | graphic real injury, mutilation, real death |
| `hate_symbol` | yes | Nazi/extremist symbols, slurs, hateful caricatures |
| `violence_threat` | yes | glorifying terrorism/mass violence, credible threats |
| `harassment_doxxing` | yes | exposing a private person's personal info |
| `self_harm` | yes | depicting/promoting suicide or self-harm |
| `drugs` | yes | hard/illegal drug use, sale, promotion |
| `scam_spam` | yes | phishing, crypto/giveaway scams, mass ads |

## Child sexual abuse material (CSAM)

Sentry does **not** classify or handle CSAM. Detection and reporting of this content
is **entirely Discord's responsibility** — Discord runs platform-level detection on
every upload and reports to NCMEC as legally required, independent of this bot. Sentry
has no CSAM category and takes no CSAM-specific action.

## Restriction mechanic

Discord role permissions are additive — a role cannot deny something another role
grants. So the bot creates a `Media Restricted` role and writes a **channel overwrite**
denying Attach Files + Embed Links in every channel it can manage. That is the only
approach that actually holds. Channels created later need `/sentry restrict` run once
to re-apply.

Restrictions never expire on their own. An admin clears them from the review case or
with `/sentry unrestrict`.

## Review cases

Each case embeds the user, origin channel, category, confidence, a non-graphic reason,
and the image's SHA-256 **fingerprint**. Flagged images are attached with `SPOILER_`
filenames so they stay blurred until a moderator clicks, so the review channel should be
mod-only.

**Images are not hoarded.** The moment a case is resolved (any button), the bot **strips
the image attachment** from the case, leaving a text-only audit record. Upheld harmful
content is removed from the channel immediately rather than sitting there indefinitely —
which matters, because a server that stockpiles such content risks being actioned by
Discord. The stored fingerprint is what lets later actions work without the image.

Three buttons:

- **Restore access** — lifts the restriction, then leaves a **Re-restrict** button so
  the decision can be reversed.
- **Uphold restriction** — keeps the restriction, then leaves a **Restore access** button
  so it can still be lifted later. (Restore ↔ Re-restrict toggle indefinitely; resolutions
  are never a dead end.)
- **Approve** — restores access, **adds the image's hash to a per-server allow-list**, and
  **DMs the user** that they may repost it themselves. The bot never reposts on the user's
  behalf; because the image is allow-listed, the user's own repost — and any future post of
  that exact image, by anyone — is not flagged again. (Without the allow-list, a repost
  would just be re-classified to the same verdict and removed in a loop.) The closed case
  keeps a single **Undo approval** button.
- **Undo approval** (shown only after Approve) — reverses the approval via the stored
  fingerprint: the image is **blocked again** (any new post of it is deleted with no Claude
  call), and **every repost the bot saw while it was approved is deleted** — their message
  IDs are tracked in state, so cleanup is exact, not a history scan. No one re-handles the
  image.

## Tuning

- **False positives** are the main failure mode, and they now cost a real deletion. The
  prompt explicitly calibrates swimwear, shirtless people, cosplay, game screenshots and
  horror makeup as clean. Start on `standard`; move to `relaxed` if your community posts
  a lot of fighting-game or medical content. The broader categories (hate symbols, drugs,
  scam/spam, etc.) widen the false-positive surface — hate-symbol detection in particular
  has to tell WWII history, the Hindu/Buddhist swastika, and anti-hate imagery apart from
  the real thing — so when a clean image does get caught, the **Approve** review button
  restores access, allow-lists the image, and tells the user they can repost it, keeping
  the cost of a mistake low.
- **Failures never take action, but are surfaced.** If the check can't complete (API
  outage, undecodable or oversize file), the message is **left up** — an outage can't
  mass-delete content — and a "Check failed — no action taken" notice is posted to the
  review channel with a jump link so a moderator can review it by hand. Transient API
  errors (429/5xx/timeouts) are retried with backoff before giving up.
- **Confidence threshold** (`/sentry threshold`) sets how sure Claude must be before an
  image is quarantined: `low` (≥0.60), `medium` (≥0.75, default), `high` (≥0.90). Raise it
  if you see false positives; lower it to catch more borderline cases. This is separate
  from **sensitivity**, which changes *what* Claude flags; the threshold filters *how
  confident* a flag must be.
- **Cost:** one Haiku call per image at ~800 input tokens, ~50 output. Identical
  re-uploads cost nothing: an in-memory cache covers the current session, and moderator
  decisions (both approvals and disapprovals) **persist to `sentry_state.json`**, so a
  reposted image that was already approved or already rejected never calls Claude again,
  even across restarts. Rates: <https://claude.com/pricing>
- **Lower `SENTRY_MAX_EDGE` to 512** to roughly halve tokens and shave latency; obvious
  cases hold up well, borderline cases degrade.
- **Videos are not scanned.** Claude vision takes images only — this includes the mp4
  behind a Tenor/Giphy GIF, though its GIF preview frames *are* scanned. Multi-frame GIF
  scanning multiplies the per-GIF cost by up to `SENTRY_GIF_FRAMES`; lower it to trade
  coverage for cost. Embed/link scanning depends on the bot reaching the image URL and
  fails open (an unreachable link is not flagged).
- Every member is scanned, including moderators and admins. Note that the
  `Media Restricted` role cannot actually constrain a user with Administrator or
  the server owner — Discord permissions override channel overwrites for them — so
  their flagged images are still deleted and a case still opens, but no restriction
  sticks.

## Tiers

Sentry is gated so only allowlisted ("premium") servers get the full feature set:

- **Free** (default for any new server): **watches every category** and reports flags to
  the review channel, but is locked to **watch-only** — nothing is removed — capped at
  **`SENTRY_FREE_SCAN_LIMIT` (50)** scans per UTC day, and a "powered by" ad is posted
  publicly on each detection.
- **Premium** (allowlisted): actually **removes** flagged images (`/sentry dryrun off`) and
  has no scan cap.

The allowlist is the bot owner's, managed via `SENTRY_ALLOWLIST` (comma-separated guild
IDs), the `/sentry allowlist` command (owner-only), or the **admin dashboard**.

**Admin dashboard.** Set `SENTRY_ADMIN_TOKEN` to enable a small web UI for managing the
allowlist (list servers, grant/revoke premium, add by ID). It binds to `127.0.0.1:8899`
by default, so reach it over an SSH tunnel — e.g.
`gcloud compute ssh <vm> -- -L 8899:localhost:8899`, then open
`http://localhost:8899/?token=YOUR_TOKEN`. Set `SENTRY_ADMIN_BIND=0.0.0.0:PORT` to expose
it publicly (token-protected), but a tunnel is safer.

## Operational notes

- State lives in `sentry_state.json`. Back it up; both values are recoverable by
  re-running `/sentry setup`.
- **Audit log.** Every removal, check-failure, and moderator action is appended as one
  JSON object per line to `audit.jsonl` (next to the state file; override with
  `SENTRY_AUDIT_LOG`, rotated at 5 MB × 5). It records the user, channel, message id,
  category, confidence, reason, and SHA-256 — so you can reconstruct exactly what
  happened and why **even if the bot is kicked from the server** and the Discord-side
  cases become inaccessible. Read it with e.g. `jq . audit.jsonl`.
- **Blocked-image archive (opt-in).** Set `SENTRY_ARCHIVE_BLOCKED=N` to save each blocked
  image's bytes to `blocked/<sha256>.<ext>` (next to the state file) for `N` days, so you
  can eyeball false positives directly. Off by default. The filename's sha256 matches the
  audit log, so you can cross-ref.
- Review buttons are persistent — they keep working after a restart.
- One process, asyncio semaphore capping concurrent API calls at 4. An image-spam raid
  queues rather than fanning out, which lengthens the visibility window under load.
