# Rooting LG LF653V (webOS 2.0, m14tv SoC)

Notes and PoC from rooting an **LG LF653V** TV running **webOS 2.0** (`3.16.0-p.3.badlands.m14tv`, ARMv7, ~914 MB RAM, phys `0x0–0x3aefffff`).

## TL;DR

All public exploits (RootMyTV v1/v2, WTA, DejaVuln, faultmanager, SlopBro, CVE-2023-6319) require **webOS ≥3.4** — nothing covers 2.x. Working path for webOS 2.0:

**Developer Mode app → SSH as `prisoner` (port 9922) → the prisoner user is in group `compositor`, which owns `/dev/mem` rw → scan physical memory for own cred struct, zero uid/gid + set caps → root.**

## Exploit path

1. Install **Developer Mode** from LG Content Store, log in, enable **Dev Mode** + **Key Server** (works only while the app is on screen; 6-digit passphrase shown).
2. Fetch SSH key: `curl -o webos_rsa http://TV_IP:9991/webos_rsa` (decrypt with passphrase).
3. `ssh -p 9922 -i webos_rsa -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa prisoner@TV_IP`
4. Inside the jail: `id` → `groups=44(video),505(compositor),509(se),777(crashd)`. `/dev/mem` is `crw-rw---- root compositor` → **direct kernel memory r/w as unprivileged user**.
5. Run `pwn4` (see `pwn4.c`): scans `/dev/mem` for the 8-word `uid,gid,uid,gid,...` pattern of own `cred` struct, validates shape (`usage ≤ 64`, `securebits==0`, `cap_effective==0`, `cap_bset lo==0xffffffff`), then zeroes uid/gid fields and fills caps → `setresuid(0,0,0)` → root.

### cred layout on this kernel (measured via `dump.c`)

```
usage | uid gid suid sgid euid egid fsuid fsgid | securebits
cap_inheritable(8B) cap_permitted(8B) cap_effective(8B) cap_bset(8B = ffffffff,ffffffff)
```

~10–20 real cred hits per scan (devmode sshd session processes). Hits with pointer-looking `usage` values are freed slab objects — skip them (`usage > 64`).

## What works / what doesn't

| Thing | Status |
|---|---|
| `/dev/mem` cred patch → root | **works** |
| root sshd on :22 (openssh from devmode pkg) | works, needs `-f` for sshd_config + `/dev/ptmx` (`mknod /dev/ptmx c 5 2`) |
| dropbear (from hbchannel IPK) on :2222 | works, needs `/var/lib/webosbrew/sshd/` dir (patched path) |
| Entware armv7sf-k3.2 in `/media/opt` → bind `/opt` | works, opkg/htop/mc fine |
| `start-devmode.sh` boot hook | **broken** — the devmode service **regenerates** this file at every start |
| `jail_app.conf` edit | **blocked** — signature verified (`verify_sig`, appsigning bundle) |
| replacing `binaries-armv71/opt/openssh/sbin/sshd` | **blocked** — `binaries-armv71/` mounted ro |
| devmode sshd daemon | runs **as root, outside jail** (`/proc/PID/root` = `/`) — jail applies only to login sessions |
| `/etc/shadow` | absent; passwd-bind `root::` works for pubkey auth |

## Persistence — OPEN PROBLEM

No reliable boot hook found yet. `devmode_enabled` dir marker makes the devmode service auto-start at boot (jailer watches `/var/luna/preferences/devmode_enabled`), spawning `/bin/sh start-devmode.sh` as root **outside the jail** — but the file content is regenerated from an in-memory template (fd-fed script, `/bin/sh -e /proc/self/fd/9`), so edits don't survive.

Ideas not yet explored: patching the template inside the generating binary, registering a custom luna service via ls-hubd API, NVM Debug Mode (EEPROM flag → serial root — the hardware fallback that always works on pre-2018 platforms).

## Re-root after reboot (~2 min)

Key Server ON → fetch rsa → `ssh prisoner@:9922` → upload `pwn4` → run → root; relaunch sshd/dropbear manually.

## Files

- `pwn4.c` — cred patcher with strict cred-shape validation + auto-spawn telnetd
- `pwn3.c` — earlier revision
- `dump.c` — read-only scanner dumping bytes around pattern hits (used to learn cred layout)

## Warning

Blind memory patching can crash the TV (a careless first scan wrote to ~6000 false-positive sites — TV survived but rebooted itself). Validate cred shape before writing. Root telnet on :23 has no auth — LAN only.
