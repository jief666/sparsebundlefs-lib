# sparsebundlefs-lib

Mount macOS sparsebundles on Linux — including modern Big Sur+ encrypted
Time Machine backups — as a single virtual disk image via FUSE. Once
mounted, you can hand the resulting `sparsebundle.dmg` to a tool like
[apfs-fuse](https://github.com/sgan81/apfs-fuse) to browse its contents.

This fork adds:

- **Big Sur+ Time Machine support.** Apple changed the keyblob wrap from
  3DES-CBC (algorithm `0x11`) to **AES-192-CBC** (algorithm `0x80000001`,
  `CSSM_ALGID_AES` in Apple's vendor namespace). The original lib hard-coded
  3DES and silently failed with "Unable to unwrap. Wrong password?" on any
  modern bundle. This build detects the algorithm and uses the right cipher.
- **libfuse3 migration.** Replaces the deprecated libfuse2 API with `fuse_new`
  + `fuse_loop_mt`, including an explicit `max_threads` to avoid the
  long-standing libfuse3 "Ignoring invalid max threads value" warning.
- **Thread-safe band fd cache.** The band file descriptor cache is now
  protected by a mutex, so concurrent FUSE worker threads no longer race and
  produce `errno=9 (Bad file descriptor)` for bands.
- **`-D` actually does something.** Replaced the unconditional-`printf` macro
  with real `syslog`, so `-D` (which sets `LOG_UPTO(LOG_DEBUG)`) gates
  diagnostic output. The password is never echoed — only its length and
  whether it contains non-ASCII bytes, which is enough to catch the common
  pitfalls (stray newline, smart-quote substitution, etc.).
- **A Makefile.** `make` builds `build/sparsebundlefs`.

## Building

Dependencies (Debian/Ubuntu):

    sudo apt install libfuse3-dev libssl-dev build-essential pkg-config

Then:

    make                       # produces build/sparsebundlefs
    sudo make install          # /usr/local/bin/sparsebundlefs
    make FUSE_PC=fuse          # build against libfuse2 instead
    make clean

## Usage

    sparsebundlefs [-o OPTIONS] [-f] [-s] [-D] <sparsebundle> <mountpoint>

| Flag           | Meaning                                                  |
|----------------|----------------------------------------------------------|
| `-f`           | Foreground (don't daemonize)                             |
| `-s`           | Single-threaded                                          |
| `-D`           | Print parse-time and unwrap diagnostics                  |
| `-o allow_other` | Let other users (e.g. apfs-fuse run separately) read    |
| `--pass=PW`    | Pass the password on the command line (testing only — leaks via process list) |

If `--pass=` isn't given, the tool prompts via `getpass()` on the terminal.

Exposes a single file in the mountpoint: `sparsebundle.dmg` — the (decrypted
if applicable) raw disk image, which you then mount with another tool.

## End-to-end: mount a Time Machine backup from a SMB share

Adjust paths/credentials for your environment, then:

```sh
# Configuration (fill these in)
SMB_HOST=<nas-hostname-or-ip>
SMB_SHARE=<share-name>
SMB_USER=<smb-username>
SHARE_MNT=/mnt/<share>          # where the SMB share lives
SPB_MNT=/mnt/<sparsebundle>     # where the decrypted .dmg appears
APFS_MNT=/mnt/<browse>          # where the APFS filesystem is browsed

# 1. Mount the SMB share that holds the .sparsebundle
mountpoint -q "$SHARE_MNT" || sudo mount -t cifs //$SMB_HOST/$SMB_SHARE "$SHARE_MNT" \
    -o username=$SMB_USER,vers=3.0,uid=$(id -u),gid=$(id -g)

# 2. Pick the sparsebundle
SPB=$(ls -d "$SHARE_MNT"/*.sparsebundle 2>/dev/null | head -1)
[ -z "$SPB" ] && { echo "No sparsebundle found"; exit 1; }
echo "Using sparsebundle: $SPB"

# 3. Mount the sparsebundle (will prompt for the encryption password)
sudo chown $USER:$USER "$SPB_MNT" "$APFS_MNT"   # one-time, if root-owned
sparsebundlefs -o allow_other "$SPB" "$SPB_MNT"

# 4. Verify decryption succeeded — APFS containers start with "NXSB" at offset 0x20
xxd "$SPB_MNT"/sparsebundle.dmg | head -3
#  expected: 00000020: 4e58 5342 ...    NXSB...

# 5. List the volumes and APFS snapshots inside
apfsutil "$SPB_MNT"/sparsebundle.dmg
#  Volume 0 …
#  Snapshots:
#      7276 : 'com.apple.TimeMachine.YYYY-MM-DD-HHMMSS.backup'
#      7832 : 'com.apple.TimeMachine.YYYY-MM-DD-HHMMSS.backup'

# 6. Mount a specific snapshot read-only with apfs-fuse
SNAP=<snapshot-id>
apfs-fuse -o ro,snap=$SNAP "$SPB_MNT"/sparsebundle.dmg "$APFS_MNT"

ls "$APFS_MNT"/
```

### Working with snapshots

Time Machine on APFS stores each backup as an **APFS snapshot** inside a
single "Backups of <hostname>" volume — not as a directory tree per backup.
The bundle's "live" volume only shows the most recent state; older backups
live inside snapshots that you must mount one at a time.

- **List snapshots:** `apfsutil <sparsebundle-mount>/sparsebundle.dmg`
- **Mount a snapshot:** add `-o snap=<id>` to apfs-fuse (no `snap=` mounts
  the live volume)
- **Browse a different snapshot:** unmount and remount apfs-fuse with the
  new snapshot id; or mount each to a separate directory

To see all snapshots side-by-side:

```sh
for snap in $(apfsutil "$SPB_MNT"/sparsebundle.dmg | awk '/^    [0-9]+/ {print $1}'); do
    mkdir -p /mnt/tm-$snap
    apfs-fuse -o ro,snap=$snap "$SPB_MNT"/sparsebundle.dmg /mnt/tm-$snap &
done
```

## Diagnosing a failed unwrap

If `Unable to unwrap. Wrong password ?` fires, rerun with `-D -f` and inspect
the output:

```
DIAG: password strlen=<N> has_non_ascii=0
DIAG: kdf_algorithm=103 kdf_prng=0 kdf_iter=<iter-count> kdf_salt_len=20 keyblob_size=64
DIAG: blob_enc_algorithm=0x80000001 blob_enc_iv_size=8 blob_enc_key_bits=192 ...
DIAG: AES-192-CBC unwrap pad=0x07
```

Things to check:

- **`strlen`** matches the length you intended to type — catches dropped
  characters or accidental trailing newline.
- **`has_non_ascii=1`** means the typed password contains UTF-8 multibyte
  characters. macOS may store the same-looking password with different bytes
  (smart quotes, NFD vs NFC normalization). Get the bytes via Mac terminal:
  `security find-generic-password -a "<bundle-uuid>" -w | xxd`.
- **`blob_enc_algorithm`**: `0x00000011` = legacy 3DES (older bundles),
  `0x80000001` = modern AES-192. The tool handles both; any other value is a
  format we don't know yet — please open an issue with the `-D` output.
- **`AES-192-CBC unwrap pad=0x??`**: the trailing PKCS7 padding byte. Valid
  values are `0x01`..`0x10` (3DES path: `0x01`..`0x08`). Anything else means
  the password doesn't match — PBKDF2 derived a key that produced random
  bytes when used to decrypt the keyblob.

If you can mount the same bundle on macOS with the password you have, but
this tool still rejects it, the password is being mangled somewhere between
your keyboard and PBKDF2. Save it to a file via `security find-generic-password`
on the Mac, scp it over, and feed it byte-exactly with `--pass="$(cat pw.bin)"`.

## File layout

- `src/sparsebundlefs/` — the library: token parsing, key unwrap, per-block AES-CBC decrypt
- `src/fuse/` — the FUSE wrapper (libfuse3-based)
- `src/crypto/` — embedded crypto primitives (3DES, AES, PBKDF2, HMAC-SHA1)
- `Makefile` — builds `build/sparsebundlefs`

## Credits

Original project by [Tor Arne Vestbø](https://github.com/torarnv/sparsebundlefs).
Encryption support added by [Jief Luce](https://github.com/jief666/sparsebundlefs-lib).
Big Sur+ AES-192 wrap, libfuse3 port, thread-safety fix, and Makefile added here.
