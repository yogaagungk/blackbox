# blackbox

ORBIT Suite secrets CLI: seals `.env` files with [age](https://age-encryption.org)
so the encrypted `.env.lock` can be committed, and unseals them locally with a
private key that never leaves `~/.blackbox/keys.txt`.

Status: B1 (`init`, `seal`, `unseal`), B2 (`sync --target github`) and
B3 (`sync --target lander`).

## Build

```sh
make build     # bin/blackbox
make test      # go test -race ./...
make vet
make lint
make install   # /usr/local/bin/blackbox
```

## Usage

```sh
# Once per machine: create ~/.blackbox/keys.txt (0600) and ./.blackbox.yaml
blackbox init

# Encrypt the local .env into a committable .env.lock
blackbox seal

# Restore .env from .env.lock (refuses to overwrite unless --force)
blackbox unseal

# List the repository secrets that would be set (no network, names only)
blackbox sync --target github --repo owner/name

# Upload them (sealed box, token from GITHUB_TOKEN or a hidden prompt)
GITHUB_TOKEN=... blackbox sync --target github --repo owner/name --apply

# Upload a PEM/known_hosts file as one secret, without putting it in .env
blackbox sync --target github --repo owner/name \
  --from-file DEPLOY_SSH_KEY=deploy.pem --apply

# Deliver app env to a lander daemon (token from LANDER_TOKEN or --token)
LANDER_TOKEN=... blackbox sync --target lander --url https://lander.example.com \
  --app my-api --apply
```

Flags: `--config <path>`, `--keys <path>`, `seal --in/--out/--dry-run`,
`unseal --in/--out/--dry-run/--force`, `init --force/--no-gitignore`.
`init` adds `.env` to `.gitignore` (it asks first on a terminal and defaults
to adding it in non-interactive runs).

## Security model

- The age identity is written with mode `0600`; `unseal` accepts only `0600`
  or `0400` keys and rejects anything readable or executable by group/others.
- The recipient comes from the repo-tracked `.blackbox.yaml`; `seal` prints
  its first/last characters so a swapped recipient is visible before commit.
- `init` reuses an existing machine identity in a second repo; `--force`
  rotates it and leaves a timestamped `keys.txt.bak-*` backup.
- `.blackbox.yaml` contains only the public recipient and is safe to commit;
  `.env.lock` is ciphertext and is meant to be committed.
- `.env` is added to `.gitignore` by `init`.
- Command output only names files and byte counts; plaintext and key material
  are never printed or logged.
- All writes go through a temp file plus atomic rename; unseal writes `0600`.
- `sync` reads `.env` into memory, uses libsodium `crypto_box_seal`
  (`nacl/box.SealAnonymous`) with the repository public key, and never logs
  values: the default dry run prints key names only. Blank keys, invalid key
  names and non-`A-Z_` names are skipped with a name-only warning.
- The GitHub token comes from `GITHUB_TOKEN` or a hidden stdin prompt, never a
  flag, and is never written to disk. A fine-grained PAT needs "Secrets:
  read and write" on the repository; a classic PAT needs the `repo` scope.
- `sync` without `--apply` is a dry run: it lists names only and makes no
  network call. `--env` is read from disk only; it is never printed.
- `--api`/`--url` must be https; plain http is accepted only on loopback for
  local tests, so a copied command cannot send a token over the network.
- Inline `#` comments in `.env` are part of the value and are not stripped.
  Multi-line quoted values are supported; unterminated quotes are skipped
  rather than uploaded truncated.
- Lander rejects multi-line and >8 KiB values, so those are skipped with a
  name-only warning.

## Layout

```text
cmd/blackbox        cobra commands (init, seal, unseal, version)
internal/config     path resolution and .blackbox.yaml loading
internal/domain     config schema
internal/service    key generation, age seal/unseal, .gitignore updates
```
