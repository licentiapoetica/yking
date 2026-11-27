# yking

## UI text

- Keep it terse: short labels, no explanatory paragraphs.
- No reassurances ("nothing is written to a key", "read-only", "backups are kept", …). Not in the UI, not in replies.
- Only safety-critical hints stay (lockout escape, boot recovery, single-key warnings), one line each.
- Help bar: `key label` pairs, one or two words per label.

## Replies

- Short. State what changed; no recaps of how things work unless asked.

## Building

- `/usr/local/bin/yking` is what plain `yking` runs; rebuilding does not update it. Rebuild `bin/yking` once per batch of changes, then the user presses `U` in `./bin/yking`.

## Public repo

- No real serials, hostnames, usernames, UUIDs or system file copies in code, tests or commits. Tests use invented values (serials 11111111…, user alice, *.example).
