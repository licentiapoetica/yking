# yking

TUI for setting up YubiKeys on Linux: SSH, PAM, LUKS, plug/unplug actions.

## Requirements

Go, `ykman`, `libfido2` (`fido2-assert`), `pam-u2f` (`pamu2fcfg`), `openssh`, `cryptsetup`, `systemd`. Tested on Arch with KDE, GRUB and mkinitcpio.

## Build

```
go build -o bin/yking ./cmd/yking
```

## Use

```
./bin/yking                 # TUI
yking detect                # list connected keys
yking doctor                # health check
yking history               # applied changes
yking rollback [ID]         # undo one
yking luks status|enroll|migrate|repair|wipe
```

## Status

Works: key registry, SSH keys, PAM (sudo, login, lock screen), LUKS FIDO2 unlock, lock on unplug, revoke, doctor.
Planned: Debian support, remote unlock over SSH.
