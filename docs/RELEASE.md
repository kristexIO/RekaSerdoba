# Процесс релиза

## Версия и provenance

Версия задаётся в `rekaserdoba/Cargo.toml` и `windows-client/version.py`. Commit встраивается в Linux binary через `REKASERDOBA_BUILD_SHA`. Проверка:

```bash
rekaserdoba-server --version
```

## Артефакты

Linux release содержит:

- `rekaserdoba-server`;
- `rekaserdoba-net-helper`;
- `h3_bridge`;
- CycloneDX SBOM;
- `SHA256SUMS`;
- systemd units, health check и sysctl profile.

Windows release содержит персонализированный installer, GUI, service, H3 bridge, Wintun license и `SHA256SUMS.txt`. При наличии certificate thumbprint `build.ps1` подписывает исполняемые файлы Authenticode и проверяет подпись.

```powershell
.\windows-client\build.ps1 `
  -Bundle C:\secure\client-bundle.json `
  -SigningCertificateThumbprint CERTIFICATE_THUMBPRINT
```

Персонализированный installer считается secret-bearing artifact и не публикуется в общедоступный GitHub Release.

## Порядок

1. Обновить версии и changelog.
2. Пройти CI, RustSec audit и secret scan.
3. Собрать artifacts из чистого commit.
4. Проверить checksums, SBOM, `--version` и Authenticode.
5. Развернуть на staging и выполнить compatibility release gate.
6. Создать production backup.
7. Выполнить атомарный deploy.
8. Пройти readiness и WSS/H2/H3 E2E.
9. Наблюдать метрики не менее 30 минут.
10. Сохранить backup path, commit, hashes и результаты проверки.

Если этап после production deploy не пройден, релиз откатывается целиком. Identity state и manifest sequence не откатываются вместе с бинарниками без отдельного решения.
