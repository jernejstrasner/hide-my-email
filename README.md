# Hide My Email (Raycast)

Create, search and manage your iCloud **Hide My Email** addresses straight from Raycast —
no more digging four levels deep into Settings.

## Commands

- **Search Hide My Email** — fuzzy-search all your addresses by address, label or note.
  Copy/paste an address, edit its label & note, deactivate/reactivate, or delete. Also
  has a **Sign Out (reset 2FA)** action to clear the saved session and force a fresh
  sign-in.
- **Create Hide My Email** — generate a fresh address, give it a label, reserve it, and
  it's copied to your clipboard.

## Requirements

- An **iCloud+** subscription (Hide My Email is part of iCloud+).
- Your Apple ID credentials, and a trusted device to receive the 2FA code on.

## Authentication: how it works & setup

There is **no official Apple API** for Hide My Email. This extension talks to the same
private endpoints that the iCloud.com Mail settings page uses
(`setup.icloud.com` → `pXX-maildomains.icloud.com/v1/hme/*`).

It signs in with your **Apple ID** using Apple's **SRP** handshake (your password is
never sent to Apple in the clear — SRP proves you know it without transmitting it), then
stores a **trust token** so you only need to enter a two-factor code **about once a
month**. There are no cookies to manage or re-paste.

The authenticated session (cookies + service URLs) is **cached for an hour**, so repeat
runs are instant and don't re-hit Apple's login — which also avoids Apple's rate-limiting.
If the session expires mid-use, the extension silently re-authenticates from the trust
token and retries. Use **Sign Out (reset 2FA)** in the Search command to clear everything
and start fresh.

### Setup

1. Run either command. On first launch Raycast prompts for preferences.
2. Enter your **Apple ID** (e.g. `you@icloud.com`).
3. Pick a **Password Storage** mode:
   - **Store in preferences** *(recommended)* — enter your password once; Raycast
     encrypts preferences at rest. You'll enter a 2FA code about once a month.
   - **Prompt on use** — leave the password empty. You type it whenever the cached
     session (about an hour) has expired; it is used for Apple's SRP sign-in,
     kept in memory only, and **never written to disk** by this extension.
4. The first sign-in asks for the **6-digit verification code** Apple pushes to
   your trusted devices. Enter it once; the trust token is saved for ~30 days.
5. Set **Region → China** if you use an `icloud.com.cn` account.

> **Security:** with "Store in preferences", your password lives only in Raycast's
> encrypted preferences and is used solely for Apple's SRP login — it is never sent
> to Apple in the clear and never sent anywhere else. In "Prompt on use" mode the
> extension never persists the password at all. The 2FA trust token and the cached
> iCloud session are stored in the **macOS login Keychain** (encrypted at rest by
> macOS), not in plaintext files; pre-existing plaintext values are migrated
> automatically. **Sign Out (reset 2FA)** in the Search command deletes all of it.
>
> **Honest threat model:** this protects against leaking secrets via files —
> backups, cloud-synced home folders, copied Raycast data directories. It cannot
> protect against malware already running as your user account, which can read the
> Keychain and query Raycast like any other app you run. Nothing is sent anywhere
> except Apple.

### SRP credit

The SRP-6a (GSA) implementation is provided by
[`@foxt/js-srp`](https://www.npmjs.com/package/@foxt/js-srp); the login orchestration is
ported from [foxt/icloud.js](https://github.com/foxt/icloud.js) and
[mandarons/icloudpy](https://github.com/mandarons/icloudpy).

## Development

```sh
npm install
npm run dev      # opens the extension in Raycast in development mode
npm run build
npm run lint
```

## Limitations

- Built on undocumented endpoints — Apple can change them at any time.
- iCloud caps accounts at ~750 addresses.
- An address must be **deactivated** before it can be permanently **deleted** (Apple's rule).

## Credits

API surface ported from
[dedoussis/icloud-hide-my-email-browser-extension](https://github.com/dedoussis/icloud-hide-my-email-browser-extension).
