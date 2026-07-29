# Эксплуатация RekaSerdoba

## Быстрая проверка

```bash
systemctl is-active rekaserdoba.service rekaserdoba-net-helper.service caddy.service
curl --fail --silent http://127.0.0.1:9080/readyz
curl --fail --silent http://127.0.0.1:9080/healthz
journalctl -u rekaserdoba.service -u rekaserdoba-net-helper.service --since "-15 min" --no-pager
ss -lntup
```

`/healthz` подтверждает, что процесс отвечает и экспортирует метрики. `/readyz` возвращает `200` только когда edge принимает новые подключения, helper подтвердил Unix datagram registration, H3 работает и сервер не находится в graceful drain.

## Перед релизом

```bash
cd RekaSerdoba
git status --short
cd rekaserdoba
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
REKASERDOBA_BUILD_SHA="$(git rev-parse HEAD)" cargo build --locked --release
cd ..
python rekaserdoba/tools/generate_sbom.py rekaserdoba/Cargo.lock rekaserdoba/target/release/rekaserdoba-server.cdx.json --version 0.2.0 --commit "$(git rev-parse HEAD)"
bash deploy/package-release.sh rekaserdoba/target/release /secure/release "$(git rev-parse HEAD)"
```

Пакет нельзя развёртывать, если не совпадают `SHA256SUMS`, `rekaserdoba-server --check-config` сообщает ошибку, срок TLS-сертификата меньше семи суток или systemd unit не проходит `systemd-analyze verify`.

## Деплой и rollback

```bash
sudo bash deploy/deploy-release.sh /secure/release
```

Команда выводит путь новой резервной копии. Она содержит прежние бинарники, units и конфигурацию, доступна только root и проверяется контрольными суммами. Если readiness, TLS или service state не проходят проверку, скрипт вызывает rollback автоматически.

Ручной откат:

```bash
sudo bash deploy/verify-backup.sh /var/backups/rekaserdoba/YYYYMMDDTHHMMSSZ
sudo bash deploy/rollback-release.sh /var/backups/rekaserdoba/YYYYMMDDTHHMMSSZ
```

Ключи, `server.json`, manifest sequence и TLS-файлы не меняются обычным релизом. Их ротация выполняется отдельной процедурой с собственной резервной копией.

## Реакция на сбои

| Симптом | Проверка | Действие |
|---|---|---|
| `/readyz` возвращает `503` | `rekaserdoba_network_ready`, `rekaserdoba_h3_ready`, journal helper | восстановить helper или H3; не перезапускать всё сразу |
| растёт `network_dropped_packets_total` | очереди сессий, UDP buffers, CPU | проверить нагрузку и `net.core.*`; увеличить лимиты только после измерения |
| растёт `handshake_failed_total` | время на сервере, manifest, client clock | проверить NTP и срок manifest; ключи не заменять до подтверждения причины |
| H3 недоступен, H2/WSS работают | UDP/443, nftables, TLS sync | проверить firewall и сертификат H3 |
| Windows-клиент переподключается | `reka-service.exe status`, diagnostics | проверить выбранный carrier и cooldown, затем сеть и manifest |
| release не проходит readiness | backup path из вывода | дождаться автоматического rollback и проверить его checksums |

## Диагностика Windows

```powershell
reka-service.exe version
reka-service.exe status
reka-service.exe check
reka-service.exe diagnostics C:\Temp\RekaSerdoba-diagnostics.zip
```

Архив диагностики не включает DPAPI bundle, signing seeds и gate key. Строки журнала с признаками credentials заменяются на `[redacted]`.

## Резервные копии

Хранить минимум три успешных релиза и одну отдельную зашифрованную копию identity state вне сервера. Ежемесячно проверять восстановление на staging. Удаление старых копий выполняется отдельно и только после успешного restore drill.

## Алерты

Правила находятся в `deploy/prometheus-alerts.yml`. TLS expiry дополнительно проверяет `rekaserdoba-health-check`. Метрики доступны только на loopback; для Prometheus следует использовать локальный agent или защищённый scrape tunnel.
