# Матрица совместимости

## Поддерживаемые платформы

| Компонент | Поддержка | Обязательные условия |
|---|---|---|
| Linux edge | Ubuntu Server 22.04 x86_64 | systemd, nftables, TUN, ядро с Unix datagram |
| Windows client | Windows 10 22H2 x64 | Wintun, права администратора для установки |
| Windows client | Windows 11 23H2 и 24H2 x64 | Wintun, права администратора для установки |
| H3 carrier | UDP/443 | WebTransport, TLS 1.3, доступный direct endpoint |
| H2 carrier | TCP/443 | Caddy reverse proxy, streaming request/response |
| WSS carrier | TCP/443 | HTTP Upgrade через Caddy |

ARM, macOS, Linux desktop client, IPv6 tunnel payload и 32-bit Windows не входят в текущий release gate.

## Совместимость протокола

| Версия сервера | Handshake | Data plane | Control plane | Manifest | Windows client |
|---|---|---|---|---|---|
| 0.2.x | RS-HS/1 | RS-DP/1 | RS-CP/1 | COSE_Sign1 sequence 1+ | 0.2.x |

Изменение wire format требует нового protocol version и conformance vectors. Минорный релиз не должен менять существующие frame type, HKDF label, transcript или gate MAC.

## Release gate

Перед объявлением совместимости должны пройти:

- Rust unit/property tests и clippy без предупреждений;
- Python protocol-tool tests;
- Windows client tests;
- WSS, H2 и H3 handshake/data/fragment/rekey E2E;
- WSS → H2 migration;
- helper restart с сохранением edge;
- rollback на предыдущий пакет;
- проверка Windows 10 и Windows 11 на реальных VM.

Последние два Windows пункта нельзя считать выполненными только по GitHub Actions; они требуют подписанного установщика и VM smoke test.
