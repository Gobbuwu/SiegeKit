# Scanning a preview behind its host's login

Hosting providers put preview deployments behind a login: Vercel's "Vercel Authentication" (Standard Protection, on by default) answers every request without a Vercel login with a 302 to `vercel.com/sso-api`. Turning the login off makes every preview of the project public while it is off. Instead, give SiegeKit the provider's bypass header in `SIEGEKIT_EXTRA_HEADERS` (ADR 0070).

SiegeKit sends the headers on every request to the target's origin: the proof-of-control fetch, the reachability check, its own checks, and every tool's requests (added by SiegeKit's proxy on your machine, so the secret never enters a tool's container). It never sends them to another host (`--backend-url`, `--storage-url`, `--mail-catcher`). The plan line names the headers, never their values; the reports hide every value wherever a tool quoted it (`[hidden: SIEGEKIT_EXTRA_HEADERS value]`); the audit log records only the header names.

## Vercel, step by step (Linux or WSL)

1. In Vercel: the project, **Settings**, **Deployment Protection**, **Protection Bypass for Automation**: create a secret. Leave Vercel Authentication on. Vercel documents the header as `x-vercel-protection-bypass` and says this feature "is available on all plans" ([Vercel docs](https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation)).
2. Get the proof-of-control token for the preview's host. A deployed scan needs one, and the first run prints it and stops:

   ```bash
   siegekit scan --deployed https://PREVIEW-HOST
   ```

   It prints a line `siegekit-verify=<32 hex characters>` and where to publish it.
3. Publish the token at `/.well-known/siegekit-verify.txt` on the preview, for example as `public/.well-known/siegekit-verify.txt` in a Next.js app, holding exactly that line, and push it so the preview is rebuilt. Each preview host has its own token: a branch preview's host differs from the production host. (A DNS TXT record on `_siegekit-verify.HOST` works too, for a host whose DNS you control.)
4. Type the secret at a hidden prompt, so it is not in your shell history, in a file or on screen, and check that something was read:

   ```bash
   read -rsp 'Bypass secret: ' S; echo; echo "read ${#S} characters"
   ```

   If it says 0 characters, run it again: a multi-line paste can leave it empty. (SiegeKit refuses an empty value anyway.)
5. Scan with the header given only to this command:

   ```bash
   SIEGEKIT_EXTRA_HEADERS="x-vercel-protection-bypass: $S" siegekit scan --deployed https://PREVIEW-HOST
   unset S
   ```

   The plan says `Every request to https://PREVIEW-HOST carries X-Vercel-Protection-Bypass from SIEGEKIT_EXTRA_HEADERS (values hidden here and in the reports)`, then `Proof of control found: well-known file`. Type the host name when asked.
6. Revoke the secret in Vercel when you no longer need it.

Without the header, the proof check is refused with `answered 302 Found (redirects are not followed)` and nothing else is sent.

## Other providers

A provider whose bypass is a request header is given the same way, one `Name: value` per line. SiegeKit has been tested only with Vercel's (Porchlet's protected Hobby preview, 2026-11-25).

## What SiegeKit refuses, before any request

- A variable that is set but holds no header, a line without `Name: value`, a name that is not a valid header name, an empty value, a value shorter than 8 characters (every value is hidden in the reports as a secret, and hiding a shorter one would hide ordinary text), a control character, and the same name twice.
- `Host`, `User-Agent` (SiegeKit labels its traffic), `Content-Type` (each request sets its own), `Content-Length`, `Accept-Encoding`, the connection headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`) and every `Proxy-` header.
- `Cookie`, `Authorization`, `X-Api-Key`, `X-Auth-Token`, `X-Access-Token`, `X-Session-Token` and any header set in `SIEGEKIT_SESSION_B` or `SIEGEKIT_SESSION_C`: these carry an app login, and the access-control check's requests with no login would then be signed in and miss real findings. Give app sessions with `--har` and the session variables instead. A custom login header with another name is not detected: do not put an app login here.
- Plain `http://` with `--deployed`: the secret would cross the internet unencrypted.

A header the person gives replaces a header of the same name that a tool or check sets.

## Limits

- Vercel's **Security Checkpoint** (a 403 bot-challenge page of about 25 KB) is not a login, and the bypass header does not get past it: on Porchlet's preview it started after one run of 246 requests at 10 requests a second or less. A scan that hits it is cut short; SiegeKit does not detect that yet (issue #86).
- A value is hidden in the reports as typed. A tool that quoted it encoded (URL- or HTML-escaped) would not be caught; a value of letters, digits and `-._~` reads the same in every encoding.
- Like every environment variable, other processes of the same user can read it while SiegeKit runs.
