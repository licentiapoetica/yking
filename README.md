# yking

TUI for setting up YubiKeys on Linux: SSH, PAM, LUKS, PGP, KeePassXC, plug/unplug actions. `man yking` after installing.

## Requirements

Go, `ykman`, `libfido2` (`fido2-assert`), `pam-u2f` (`pamu2fcfg`), `openssh`, `cryptsetup`, `systemd`, `gnupg` (PGP). Tested on Arch with KDE, GRUB and mkinitcpio.

## Build and install

```
go build -o bin/yking ./cmd/yking
sudo install -m 755 bin/yking /usr/local/bin/yking   # first time only
sudo install -Dm 644 docs/yking.1 /usr/local/share/man/man1/yking.1
```

Building does not update the installed copy. After a rebuild, run `./bin/yking` and press `U`.

## Use

```
./bin/yking                 # TUI
yking detect                # list connected keys
yking doctor                # health check
yking history               # applied changes
yking rollback [ID]         # undo one
yking rollback --user [ID]  # undo a change to your own files (u2f_keys, ~/.ssh/config)
yking luks status|enroll|migrate|repair|wipe|backup|passphrase remove
```

## Uninstall

Revert first — PAM and boot use yking's files:

1. PAM: `yking` → `p`, set every service to `off`, apply.
2. LUKS boot switch: `yking history`, then `yking rollback ID` for "LUKS: switch boot…". Optional: `yking luks wipe --slot N` removes FIDO2 slots (the passphrase stays).
3. Remove the files:

```
sudo rm /usr/local/bin/yking /usr/local/share/man/man1/yking.1 /etc/udev/rules.d/90-yking.rules /etc/udev/rules.d/69-yking-otp.rules /etc/systemd/system/yking-event@.service
sudo rm -r /etc/yking /var/lib/yking
sudo udevadm control --reload && sudo systemctl daemon-reload
rm -r ~/.local/state/yking ~/.cache/yking
```

Left alone: SSH keys (`~/.ssh/yk-main-*`), yking blocks in `~/.ssh/config`, `~/.config/Yubico/u2f_keys`.

## SSH config

yking never edits `~/.ssh/config` on its own. When deploying a key (`d`), tick
*SSH config* to also review a `Host` block for that server, or open the SSH
hosts screen (`o`) to add or update one host at a time. Each block lists every
YubiKey key deployed to the server (daily key first) with `IdentitiesOnly yes`,
so plain `ssh host` works with whichever key is plugged in. Only yking's own
`# yking-begin` / `# yking-end` blocks are changed; a hand-written section for
the same host is taken over only if it has nothing yking would drop. The result
is checked with `ssh -G` before you apply it.

## Status

Works: key registry, SSH keys and ssh config, PAM (sudo, login, lock screen), LUKS FIDO2 unlock, PGP subkeys on keys, KeePassXC challenge-response, lock on unplug, revoke, doctor.
Planned: Debian support, remote unlock over SSH.
