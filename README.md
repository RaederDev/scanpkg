# scanpkg

`scanpkg` is a `makepkg` wrapper for Arch Linux package builds. Before handing off to the real `makepkg`, it sends the current `PKGBUILD`, recent git context, install scripts, package sidecars, local patches, hooks, and other high-risk packaging files to OpenAI for a malware-risk verdict.

If the verdict crosses the configured risk threshold, the build is blocked. Otherwise, `scanpkg` executes the real `makepkg` with the original arguments.

## Requirements

- Arch Linux or an Arch-based system
- `bash`
- `curl`
- `git`
- `jq`
- `makepkg`
- an OpenAI API key

## Install

Clone the repository and put the wrapper somewhere on your `PATH`:

```bash
git clone <repo-url> ~/.local/share/scanpkg
mkdir -p ~/.local/bin
ln -sf ~/.local/share/scanpkg/scanpkg.sh ~/.local/bin/scanpkg
chmod +x ~/.local/share/scanpkg/scanpkg.sh
```

Create a local config file next to `scanpkg.sh`:

```bash
cat > ~/.local/share/scanpkg/.env <<'EOF'
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=gpt-5.6-terra
MAKEPKG_BIN=/usr/bin/makepkg
EOF
```

`MAKEPKG_BIN` must point at the real `makepkg`. Do not point it at `scanpkg`, or the wrapper will recursively call itself.

## Use Directly

From an AUR package directory:

```bash
scanpkg -si
```

`scanpkg` accepts normal `makepkg` arguments and forwards them unchanged after the scan passes.

## Use With yay

Tell `yay` to use `scanpkg` as its makepkg command:

```bash
yay --save --makepkg ~/.local/bin/scanpkg
```

Then install AUR packages normally:

```bash
yay -S package-name
```

With the `.env` above, the call chain is:

```text
yay -> ~/.local/bin/scanpkg -> /usr/bin/makepkg
```

To verify the setting:

```bash
yay -P -g | grep -i makepkg
```

To undo the integration, reset yay's makepkg command to the system default:

```bash
yay --save --makepkg /usr/bin/makepkg
```

## Configuration

Common environment variables:

```bash
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=gpt-5.6-terra
MAKEPKG_BIN=/usr/bin/makepkg
RISK_ABORT_THRESHOLD=2
FAIL_CLOSED=1
VERBOSE=1
SCANPKG_CACHE_TTL_SECONDS=3600
```

You can set these in `.env` next to `scanpkg.sh`, or export them in your shell.

Useful controls:

- `MAKEPKG_BIN`: real `makepkg` binary to execute after a clean scan.
- `RISK_ABORT_THRESHOLD`: number of risk flags needed to block when no critical flag is triggered.
- `CRITICAL_RISK_KEYS`: space-separated risk keys that always block when true.
- `FAIL_CLOSED`: set to `0` to continue with `makepkg` if scanning fails.
- `SCANPKG_ALLOW_FAILED_PACKAGES`: temporary allowlist for blocked package names.
- `SCANPKG_CACHE_TTL_SECONDS`: how long to reuse a cached scan result for the same package version.
- `VERBOSE`: set to `0` to reduce request/response logging.

## Temporary Allowlist

If a package is blocked and you decide to proceed anyway, rerun with the allowlist shown in the error output:

```bash
SCANPKG_ALLOW_FAILED_PACKAGES="package-name" scanpkg -si
```

For `yay`, pass the environment variable into the command:

```bash
SCANPKG_ALLOW_FAILED_PACKAGES="package-name" yay -S package-name
```

## Tests

Run the shell test suite:

```bash
tests/run-tests.sh
```
