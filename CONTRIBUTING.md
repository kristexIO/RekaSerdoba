# Contributing

Contributions are welcome.

## Before opening a pull request

1. Keep protocol changes separate from deployment or GUI-only changes.
2. Update `RekaSerdoba_protocol_ru.md` when wire behavior changes.
3. Add a regression test for every protocol or lifecycle bug.
4. Never commit device bundles, private keys, server backups, packet captures, or personalized installers.

## Checks

```bash
cd rekaserdoba
cargo fmt --check
cargo test --locked
```

On Windows:

```powershell
python -m pip install cryptography==49.0.0 h2==4.3.0
$env:PYTHONPATH="$PWD\windows-client;$PWD"
python -m unittest -v windows-client\test_client.py
```

## Commit style

Use a short imperative subject, for example:

```text
Preserve H3 framing across interrupted reads
```

## Security reports

Follow [SECURITY.md](SECURITY.md). Do not disclose vulnerabilities in public issues.
