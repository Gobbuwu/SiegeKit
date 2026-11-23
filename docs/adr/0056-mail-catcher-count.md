# 0056. Emails counted at a mail catcher for the reset and sign-up checks

- Status: Accepted (design: owner 2026-11-21, Q2 C "answers by default, emails counted at a mail catcher when one is given"; ADR 0055 item 10)
- Date: 2026-11-23
- Amends: [0055](0055-rate-limit-pages.md) (item 7: when a reset page counts as limited; item 10: this is its PR 2)

## Context

The harm a password-reset page does is the emails or texts it sends. ADR 0055 judges a reset only by its answers, so a reset that answers the same each time is reported as not limited even when the app limits its emails: Gitea 1.24.6 answered 200 to 20 resets and sent 1 email (measured 2026-11-22). The approved design (Q2 C) keeps answers as the default and counts the emails at a local mail catcher when the person gives one; this is the design's PR 2. The design names Mailpit and a Gitea plus Mailpit fixture in CI.

Texts are not counted here. The one app measured sending texts, Ory Kratos 1.3.1 (through its HTTP courier to a local stand-in), has no SMS password reset (its config accepts only email for recovery), so a text count changes no finding there. The owner chose emails only (2026-11-23, "Emails only, as designed"); counting texts moves to the follow-up for send-a-code pages (SMS pumping).

## Decision

1. **`--mail-catcher URL`** names a Mailpit the person points the app's mail setting at: its web address, such as `http://127.0.0.1:8025/`, or the `--webroot` it runs under. It is checked before anything is sent (http or https, no query, fragment, user name or password, a path that starts with a single `/`). It only applies to URL targets.
2. **Where and how it is read.** It must resolve to this machine or a private network (ADR 0005's loopback and private ranges; public and blocked addresses are refused): the counts are of a test app's mail, never a hosted mailbox. SiegeKit reads it only with GET requests to Mailpit's API (`/api/v1/info`, `/api/v1/messages`) through the same pinned, read-only sender as its other own checks; it never deletes or changes a message. It is opened (one GET of Mailpit's version) at planning, and only when `reset-limit` or `signup-limit` will run; if it does not answer as Mailpit does, those two checks fail with the reason before they send anything, and the rest of the scan runs. It gets no audit entry: nothing is tested there. The plan and `plugins[].input` name it with Mailpit's version.
3. **What is counted.** Before a check, SiegeKit notes Mailpit's newest message; after the check's last request it counts the messages newer than that one sent (To, Cc or Bcc) to an email address the check's requests held: the reset's one address, each sign-up's new one. A request with no address (a reset by user name) counts every new message, and the result says so. Mailpit sends mail from a queue a little after the answer (Gitea: 1.7 s; Mattermost: 0.09 s), so SiegeKit counts once a second until no new email arrived for 5 s, or for at most 30 s; then it says emails were still arriving. A count is refused rather than guessed when the noted message is gone (deleted, or pushed out by Mailpit's 500-message default) or more than 500 arrived. The code page is not counted.
4. **When a reset counts as limited (design Q2 B).** When the answers show no limit, the count settled, and at least 1 but fewer emails arrived than requests were answered below 400, the app limits its emails: no finding, and the result says how many arrived for how many requests. When every accepted request sent an email (or more did), `reset-not-limited` says so with the count. When no email arrived (the app sends none for that address, or not to that catcher) or the count did not settle, the answers decide as in ADR 0055 and the finding says what the count showed. A limit in the answers stays the limit; the count is added to the result.
5. **Sign-ups.** The count is added to `signup-limit`'s result (what the run made, design safety rule 6); it changes no finding, since the harm there is the accounts.
6. **CI gate (design build plan).** A gate job runs Gitea 1.24.6 and Mailpit v1.27.11 on their own network, under rootless Podman and under Docker, and runs `reset-limit` and `signup-limit` from flags with `--mail-catcher`: the reset must report 1 email for 20 requests and no finding, the sign-up 20 emails and `signup-not-limited`; the gate reads Mailpit itself to cross-check the counts (1 and 20), and compares with the known answer `testdata/known-answers/gitea-mail.json`.

## Evidence

Environment for every local measurement: Claude's sandbox, 4 CPUs, cgroup v1; Docker 29.10.0 rootful and Podman 4.9.3 rootless (netavark); Go 1.26.0. Mailpit v1.27.11 (`axllent/mailpit@sha256:e22dce5b…`; the image's `org.opencontainers.image.licenses` label says MIT), Gitea 1.24.6 (`gitea/gitea@sha256:2edc102c…`, mail on, `REGISTER_EMAIL_CONFIRM`), Mattermost 12.0.2 (`mattermost/mattermost-preview@sha256:71fe9543…`, open sign-up, its rate limiter off). One run each unless stated.

| Claim | Backed by |
|---|---|
| A reset that answers the same but sends 1 email is seen as limited | Measured with the built CLI on Gitea: 20 × 200, "only 1 email arrived ... for the 20 requests", no finding; on Docker (2 runs, fresh containers) and rootless Podman. Mailpit read with curl: 1 "Recover your account". |
| A reset that emails every request is reported with the count | Measured on Mattermost: 20 × 200, 20 emails, `reset-not-limited`; on Docker and rootless Podman. curl: 20 "[Mattermost] Reset your password". |
| Sign-up emails are counted for the new addresses only | Gitea: 20 accounts, 20 "Please activate your account" to `siegekit-new-...@example.com`; Mattermost: 20 "You joined"; both engines. `TestScanURLMailCatcher` adds a message to another address, not counted. |
| Mailpit's API shape | Its real answers are kept in `internal/mailcatcher/testdata` and read by `TestRealAnswers`; `start` and `limit` page the list newest first (measured). Gitea's port answers 404 to `/api/v1/info`, and `TestOpen` refuses it. |
| The rules hold when broken | `TestCount` (pages, Cc and Bcc, any case, arrivals during the read, a missing mark, over 500), `TestSettle` (fixed clock: quiet, still arriving at 30 s, cancel), `TestOpen` (public and link-local addresses, non-Mailpit answers, a closed port; GET only), `TestAddresses` and `FuzzAddresses` (30 s, about 321,000 runs locally), `TestMailCount` (every case of item 4), `TestScanURLMailCatcher` (flag mistakes refused before any request or audit entry; a non-Mailpit catcher fails the two checks before they send; an unused catcher is never asked). |
| Planted cases are found | `TestPagesFindPlantedIssues` (test app, real clock): a reset that emails every request is reported, one that emails an address once is not. Changing item 4's `<` to `<=` makes it miss the planted one (checked); dropping the "settled" condition fails `TestMailCount` (checked). |
| The gate's answer | The gate job's steps run locally on fresh Docker containers met `gitea-mail.json`; the same report without `--mail-catcher` fails it (`reset-not-limited` new). |
| The gate on cgroup v2 | CI gate run 45110478104 on 66b8eaf: the `mail` job met `gitea-mail.json` with the app on rootless Podman 5.7.0 and on Docker 29.4.2 (cgroup v2), and the gate's own read of Mailpit found 1 reset email and 20 activation emails on both. |
| Time added | 5.0 s per counted check (Gitea reset: 19.0 s without, 24.1 s with). |

## Consequences

- A reset whose app limits its emails is no longer reported when the person gives a Mailpit; without one, nothing changes from ADR 0055, and the finding names the flag.
- A count of 0 falls back to the answers. Measured: Gitea sends an account no second reset email for a few minutes (none 103 s and 167 s after one, one 273 s after), so a run soon after another reports `reset-not-limited` with "no email arrived" in its message.
- Not covered: texts (owner 2026-11-23: emails only; texts go with the send-a-code follow-up); mail catchers other than Mailpit, and a Mailpit API behind a password (the check fails with the reason); emails that arrive more than 5 s after the previous one; an app that sends mail elsewhere and copies it to Mailpit.
- A per-address email limit is not a per-client one: an attacker who resets many addresses still sends one email each. The result says only that this address's emails were limited.

## Alternatives considered

- Answers only (design Q2 A): kept as the default; it gave the false "not limited" on Gitea.
- Counting only the total of new messages (no addresses): simpler, but another email in the window (a sign-up's, a login alert) would be counted; the address filter is used whenever a request holds an address.
- A fixed wait instead of "5 s with no new email": a fixed wait is either long for every run or short for a slow queue.
- Deleting Mailpit's messages before each check for a clean count: changes the person's data, so not done.
