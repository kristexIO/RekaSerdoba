# Модель угроз

## Защищаемые активы

- server signing seed, client signing seeds и gate keys;
- manifest authority и sequence state;
- TLS private key;
- конфиденциальность и целостность tunnel traffic;
- доступность H3, H2, WSS и network helper;
- маршруты и DNS policy Windows-клиента.

## Границы доверия

Интернет, Caddy, Rust edge, privilege-separated helper, Linux kernel TUN, Windows LocalSystem service, GUI и offline provisioning рассматриваются как отдельные границы. GUI не получает plaintext credentials. Edge не получает `CAP_NET_ADMIN`; helper не выполняет handshake и не читает identity keys.

## Основные угрозы и меры

| Угроза | Мера |
|---|---|
| replay gate или records | временное окно, nonce cache, per-epoch replay window |
| подмена сервера | Ed25519 identity внутри encrypted handshake и signed manifest |
| подмена клиента | Ed25519 client authentication после X25519 exchange |
| downgrade carrier | signed ordered manifest, одинаковый inner protocol |
| manifest rollback | persistent sequence state на клиенте |
| path traversal H3 decoy | canonical path containment и запрет symlink escape |
| memory/task exhaustion | carrier size limits, bounded queues, admission rate, semaphore limits |
| helper crash | registration ACK readiness, reconnect, systemd supervision |
| утечка bundle | machine-scope DPAPI и отсутствие bundle в diagnostics |
| компрометация release | checksums, embedded commit, SBOM, CI audit, optional Authenticode |
| опасная конфигурация | `--check-config`, subnet/duplicate checks, TLS key permission check |

## Остаточные риски

Протокол не проходил независимый криптографический аудит и формальную верификацию. Gate скрывает дорогой handshake, но не является полной DDoS-защитой. LocalSystem compromise на клиенте и root compromise на сервере находятся вне защищаемой модели. Traffic analysis, блокировка endpoint и принудительный отказ всех carrier остаются возможными.

Production с критичными данными требует внешнего аудита, 24-часового chaos soak, регулярной ротации и отдельного защищённого хранилища ключей.
