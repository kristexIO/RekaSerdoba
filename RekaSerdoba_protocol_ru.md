# RekaSerdoba/1: полностью самостоятельный VPN-протокол для сетей с DPI и ТСПУ

> Статус: исследовательская архитектура и черновик спецификации 0.1<br>
> Дата среза источников: 28 июля 2026 года<br>
> Первая целевая конфигурация: Windows 10/11 client, Debian/Ubuntu server<br>
> Предпочтительный язык: Rust<br>
> Внутренний VPN-протокол: полностью собственный; WireGuard/OpenVPN/VLESS не используются<br>
> Стандартные криптографические примитивы: X25519, Ed25519, HKDF-SHA-256, ChaCha20-Poly1305

> **Предупреждение о безопасности.** RekaSerdoba/1 — новый криптографический протокол. Даже подробная спецификация и корректное использование стандартных примитивов не доказывают его безопасность. До независимого криптографического анализа, формальной проверки state machine, fuzzing и внешнего аудита его нельзя применять для защиты критичных данных или пользователей с высоким риском.

## Аннотация

RekaSerdoba — проект собственного L3 VPN, создаваемого с нуля. Он не является оболочкой над WireGuard и не меняет чужой VPN wire format. Проект самостоятельно определяет:

- handshake и взаимную аутентификацию;
- transcript и key schedule;
- форматы handshake, control и data records;
- шифрование IP-пакетов;
- anti-replay window;
- fragment/reassembly;
- регулярное обновление ключей и полный ephemeral rekey;
- session resumption без 0-RTT data;
- перенос сессии между сетями и внешними transport carriers;
- signed configuration manifests;
- Windows routing, DNS и kill switch;
- Linux forwarding, NAT и multi-user policy.

Криптографические алгоритмы не изобретаются. RekaSerdoba использует опубликованные и широко реализованные примитивы:

- X25519 из [RFC 7748](https://datatracker.ietf.org/doc/rfc7748/) для ephemeral Diffie–Hellman;
- Ed25519 из [RFC 8032](https://www.rfc-editor.org/info/rfc8032/) для долгосрочной аутентификации;
- HKDF из [RFC 5869](https://www.rfc-editor.org/info/rfc5869/) для разделения ключей;
- ChaCha20-Poly1305 из [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) для AEAD;
- SHA-256 и HMAC-SHA-256 для transcript и finished proofs.

Внешний наблюдатель не должен видеть уникальный RekaSerdoba handshake. Протокол работает внутри сменных стандартных carriers:

1. HTTP/3 + MASQUE-подобный authenticated tunnel — основной режим;
2. HTTP/2 поверх TLS/TCP — fallback при нарушении UDP;
3. WebSocket Secure — последний совместимый fallback.

На том же endpoint работает настоящий сайт. Неавторизованное подключение не получает характерный ответ VPN. Carrier можно заменить без изменения внутренней криптографии.

Главная цель — не обещать абсолютную нераспознаваемость, а:

- убрать дешёвую постоянную сигнатуру;
- повысить стоимость точечной блокировки;
- сохранять внутреннюю end-to-end security при смене carrier;
- диагностировать разные виды сетевого вмешательства;
- безопасно обновлять внешний профиль без обновления всего клиента.

---

## 1. Что означает «протокол написан с нуля»

### 1.1. Что действительно собственное

В RekaSerdoba собственными являются:

- protocol roles и state machines;
- handshake `RS-HS/1`;
- data plane `RS-DP/1`;
- control plane `RS-CP/1`;
- carrier binding `RS-CB/1`;
- binary encoding;
- transcript rules;
- cryptographic key schedule;
- packet number и replay rules;
- rekey protocol;
- migration protocol;
- fragmentation;
- server admission;
- client/server configuration model;
- error taxonomy;
- implementation architecture.

### 1.2. Что берётся как стандартный строительный блок

Использование X25519 или ChaCha20-Poly1305 не делает протокол «копией WireGuard» так же, как использование TLS не делает два веб-приложения одним продуктом. Это криптографические функции, а не готовый VPN.

RekaSerdoba не реализует арифметику кривых и AEAD вручную. Используются поддерживаемые библиотеки с test vectors. Собственная реализация математических примитивов дала бы риски:

- nonce reuse;
- invalid point handling;
- timing side channels;
- signature malleability;
- ошибки Poly1305;
- неправильная очистка памяти;
- несовместимость между платформами.

### 1.3. Что можно заимствовать у других протоколов

Идеи можно изучать и переосмысливать:

- transcript-bound key schedule из TLS 1.3;
- подписанный ephemeral Diffie–Hellman из SIGMA-подобных AKE;
- anti-replay bitmap из IPsec;
- roaming из WireGuard;
- cookie-before-state из IKE/WireGuard/QUIC;
- pluggable transports из Tor;
- настоящий decoy из Trojan/REALITY/WebTunnel;
- HTTP Datagrams и Capsules из MASQUE;
- signed manifests и rollback protection из secure update systems.

Но их on-wire сообщения, crypto state и конфигурации не копируются.

---

## 2. Честные гарантии и ограничения

### 2.1. Цели безопасности

После завершения handshake RekaSerdoba стремится обеспечить:

- взаимную аутентификацию client и server;
- confidentiality и integrity каждого inner IP packet;
- perfect forward secrecy для сессии;
- client identity hiding от пассивного наблюдателя внешней сети;
- replay protection;
- downgrade resistance;
- key separation между handshake, control, data, migration и resumption;
- past-key protection после удаления старых epoch secrets;
- восстановление будущей секретности после полного signed ephemeral rekey, если долгосрочные identity keys не скомпрометированы;
- carrier independence;
- отсутствие доверия к DNS для аутентификации внутреннего server identity;
- отсутствие VPN-специфичного ответа неавторизованному scanner.

### 2.2. Цели доступности

- H3/UDP как быстрый carrier;
- H2/TCP и WSS как независимые fallbacks;
- несколько endpoint в signed manifest;
- session migration без смены client identity;
- сохранение TUN interface при замене carrier;
- диагностические error classes;
- bounded retries с jitter;
- работа при loss, reorder и NAT rebinding;
- IPv4 и IPv6.

### 2.3. Что нельзя гарантировать

Нельзя обещать работу при:

- блокировке всех известных server IP;
- блокировке всего UDP и длительного HTTPS;
- allowlist-модели доступа;
- полном отключении международной связности;
- компрометации Windows client или Linux server;
- установке противником доверенного root CA и контроле устройства;
- глобальной корреляции трафика на обоих концах;
- краже profile signing key;
- законодательном или инфраструктурном запрете hosting.

Фраза «100% неблокируемый VPN» в спецификации и маркетинге запрещена.

### 2.4. Уровень зрелости

До аудита допустимы только:

- laboratory interoperability;
- тесты на собственных устройствах и серверах;
- controlled measurements;
- публикация спецификации для review.

Даже успешный penetration test не заменяет cryptographic review.

---

## 3. Российская модель DPI и ТСПУ

### 3.1. Архитектура

[Федеральный закон № 90-ФЗ](https://publication.pravo.gov.ru/document/view/0001201905010025) создал правовую основу централизованного управления трафиком и размещения ТСПУ в сетях операторов. Официальный ЦМУ ССОП описывает централизованное управление, мониторинг и обязательные указания.

Peer-reviewed исследование [Xue et al., «TSPU: Russia’s Decentralized Censorship System»](https://ensa.fi/papers/tspu-imc22.pdf) показывает модель, важную для проектирования:

- устройства работают inline;
- физически они распределены по множеству ISP;
- policy может задаваться централизованно;
- оборудование располагается близко к access networks;
- один маршрут может пересекать несколько устройств;
- асимметричная маршрутизация даёт разную видимость направлений;
- legacy ISP filters продолжают действовать параллельно;
- результат различается по ASN, региону, access type и времени.

ТСПУ нельзя упрощать до «одного firewall на границе страны».

### 3.2. Наблюдаемые признаки

Публичные измерения подтверждали анализ:

- IP address и port;
- TLS SNI;
- структуры ClientHello;
- QUIC version и размер Initial;
- fixed protocol headers;
- число packets;
- направление;
- response behavior;
- flow state;
- rate и byte budgets.

Вмешательство включало:

- RST/ACK;
- packet modification;
- symmetric drop;
- drop после нескольких сообщений;
- throttling через loss;
- protocol-specific disruption;
- IP-level block.

Исследование [«OpenVPN is Open to VPN Fingerprinting»](https://arxiv.org/abs/2403.03998) не является описанием конкретного ТСПУ, но демонстрирует реалистичный DPI threat: passive classification, packet sizes и active probing вместе распознавали более 85% OpenVPN flows и большинство проверенных «obfuscated» конфигураций.

### 3.3. Active probing: не смешивать два понятия

Для российских сетей хорошо подтверждены:

- inline анализ пользовательской сессии;
- ожидание server response;
- state после нескольких packets;
- временная блокировка flow;
- IP lists.

Публичных доказательств систематического out-of-band probing каждого VPN endpoint меньше. RekaSerdoba всё равно включает его в threat model, но не выдаёт предположение за установленный факт.

### 3.4. Следствия для протокола

- custom UDP handshake нельзя выпускать наружу;
- один TLS ClientHello fingerprint недостаточен;
- random-looking stream может стать отдельным классом;
- псевдо-QUIC из нескольких bytes хуже настоящего QUIC;
- IP agility и protocol agility решают разные задачи;
- retries могут сами создать fingerprint;
- decoy должен быть настоящим сервисом;
- carrier должен меняться независимо от inner protocol;
- нужно тестировать reset/drop/rate/byte-budget, а не только полный block.

---

## 4. Threat model

### 4.1. Сетевой противник

Противник может:

- видеть IP, port, SNI без ECH, ALPN и открытые QUIC/TLS параметры;
- считать sizes, directions, timings и packets;
- хранить state;
- читать исходный код;
- блокировать DNS, IP, ASN, SNI, QUIC и protocol classes;
- drop, delay, reorder, duplicate и reset packets;
- ограничивать rate или число переданных bytes;
- подключаться к endpoint самостоятельно;
- повторять записанные requests;
- сканировать IPv4 и certificates;
- манипулировать transport fallback;
- наблюдать несколько участков маршрута.

### 4.2. Криптографический противник

Предполагается, что противник:

- может полностью контролировать carrier bytes;
- может завершать внешний TLS на недоверенном relay в двуххоповом режиме;
- знает protocol;
- может компрометировать текущие traffic keys, но не обязательно identity keys;
- пытается вызвать nonce reuse, rollback, replay, reflection, unknown-key-share и state exhaustion.

### 4.3. Базовые предположения

- X25519, Ed25519, HKDF, SHA-256/HMAC и ChaCha20-Poly1305 не сломаны;
- OS CSPRNG работает;
- identity private keys изначально доставлены безопасно;
- client имеет аутентичный profile signing public key;
- server имеет registry client identities;
- реализации проверяют all-zero X25519 output;
- старые secrets удаляются best effort.

### 4.4. Вне модели

- malware на client;
- malicious kernel/driver;
- global passive end-to-end correlation;
- traffic analysis при очень длинном наблюдении;
- forced app-level VPN detection;
- malicious destination;
- coercion hosting provider;
- denial of all external connectivity.

---

## 5. Архитектура RekaSerdoba

```text
┌──────────────────────── Windows ─────────────────────────────┐
│ reka-ui.exe                                                  │
│      │ authenticated named pipe                              │
│ reka-service.exe                                             │
│ ├── DPAPI key store                                          │
│ ├── signed manifest verifier                                 │
│ ├── Wintun + route/DNS manager                               │
│ ├── WFP kill switch                                          │
│ ├── RS-HS/1 handshake                                        │
│ ├── RS-DP/1 encrypt/decrypt                                  │
│ ├── RS-CP/1 rekey/migration                                  │
│ └── carrier manager                                          │
│      ├── H3                                                  │
│      ├── H2                                                  │
│      └── WSS                                                 │
└──────────────────────────┬───────────────────────────────────┘
                           │ standard TLS/QUIC carrier
                  DPI / TSPU / Internet
                           │
┌──────────────────────────▼───────────────────────────────────┐
│ Linux edge                                                   │
│ ├── real H2/H3 website                                       │
│ ├── stateless admission                                      │
│ ├── RS-HS/1 server                                           │
│ ├── RS-DP/1 endpoint                                         │
│ ├── client policy/address registry                           │
│ ├── TUN interface                                            │
│ ├── nftables forwarding/NAT                                  │
│ └── signed manifest endpoint                                 │
└──────────────────────────────────────────────────────────────┘
```

### 5.1. Слои

```text
Inner IP packets
  ↓
RS-DP/1 frames
  ↓
RS-DP/1 AEAD records
  ↓
RS-CB/1 carrier messages
  ↓
HTTP/3, HTTP/2 or WebSocket
  ↓
TLS/QUIC
  ↓
Internet
```

Внутренний AEAD обязателен, несмотря на внешний TLS. Это:

- сохраняет end-to-end confidentiality через ingress relay;
- не позволяет CDN/edge читать IP packets;
- делает migration между carriers независимой;
- связывает data с собственной authenticated session;
- защищает от ошибки или компрометации внешнего terminator.

### 5.2. Protocol roles

`Initiator` — Windows client.<br>
`Responder` — Linux VPN server.<br>
`Ingress` — optional carrier terminator/relay.<br>
`Exit` — узел, который завершает RS-HS/RS-DP и маршрутизирует IP.

В личном MVP Responder и Exit — один сервер. Ingress отсутствует.

### 5.3. Идентичности

Server имеет долгосрочную Ed25519 identity:

```text
S_id_sk: 32-byte seed/private representation in library
S_id_pk: 32-byte public key
```

Client имеет отдельную Ed25519 identity:

```text
C_id_sk
C_id_pk
client_id = first_16_bytes(
  SHA-256("RekaSerdoba client id" || C_id_pk)
)
```

`client_id` — selector, а не секрет. Server registry связывает его с:

- `C_id_pk`;
- allowed tunnel addresses;
- routes;
- quotas;
- revocation state;
- independent admission key.

Identity signing keys MUST NOT использоваться как X25519 keys.

### 5.4. Admission key

Каждое устройство получает случайный 32-byte `K_gate`, независимый от identity key. Он нужен только для:

- дешёвой проверки HTTP carrier request;
- защиты endpoint от probing;
- ограничения DoS до запуска handshake.

Компрометация `K_gate` не позволяет расшифровать VPN и не заменяет Ed25519 authentication. Но она позволяет открыть дорогой handshake path, поэтому key отзывается отдельно.

---

## 6. Cryptographic suite

### 6.1. Suite 0x0001

Обязательная suite RekaSerdoba/1:

```text
KEX:        X25519
Signature:  Ed25519
Hash:       SHA-256
KDF:        HKDF-Extract/HKDF-Expand with HMAC-SHA-256
AEAD:       ChaCha20-Poly1305
```

В версии 1 нет negotiation нескольких suites. Отсутствие negotiation уменьшает downgrade surface. Новая suite требует новой версии manifest и явной policy.

### 6.2. Domain separation

Все hashes, signatures и HKDF info начинаются с length-prefixed ASCII label:

```text
"RekaSerdoba/1"
"RekaSerdoba/1 server signature"
"RekaSerdoba/1 client signature"
"RekaSerdoba/1 handshake key"
"RekaSerdoba/1 data c2s"
"RekaSerdoba/1 data s2c"
"RekaSerdoba/1 control c2s"
"RekaSerdoba/1 control s2c"
"RekaSerdoba/1 migration"
"RekaSerdoba/1 resumption"
"RekaSerdoba/1 epoch update"
"RekaSerdoba/1 full rekey"
```

Один derived key не используется для двух назначений.

### 6.3. Encoding primitives

Все integers — unsigned big-endian.<br>
`u8`, `u16`, `u32`, `u64` имеют фиксированный размер.<br>
`opaque<N>` — ровно N bytes.<br>
`vector16` — `u16 length || bytes`.<br>
`vector32` — `u32 length || bytes`.

Handshake не использует JSON/CBOR. Fixed binary encoding снижает canonicalization ambiguity. Unknown extension кодируется TLV:

```text
extension_type: u16
extension_len:  u16
extension_data: bytes
```

Extensions сортируются по type по возрастанию. Duplicate type запрещён. Unknown critical extension (`type & 0x8000 != 0`) завершает handshake.

### 6.4. Transcript

Каждое handshake message сериализуется один раз в canonical wire encoding:

```text
message_type: u8
message_len:  u32
payload:      message_len bytes
```

Transcript:

```text
T0 = SHA-256("RekaSerdoba/1 transcript")
Tn = SHA-256(T(n-1) || encoded_message_n)
```

Signatures и Finished MAC всегда включают соответствующий transcript state. Parser MUST сохранять exact received encoding и не пересобирать message из object model.

### 6.5. HKDF helper

```text
ExpandLabel(secret, label, context, length) =
  HKDF-Expand(
    secret,
    u16(length) ||
    u8(len("RekaSerdoba/1 " || label)) ||
    "RekaSerdoba/1 " || label ||
    u16(len(context)) ||
    context,
    length
  )
```

`length` для всех v1 secrets равен 32, IV — 12.

### 6.6. AEAD nonce

Для каждого direction и key epoch:

```text
nonce = static_iv XOR left_pad_96(packet_number)
```

Packet number начинается с 0 и никогда не повторяется под одним key/IV. Receiver aborts session до wrap. Key update происходит значительно раньше.

ChaCha20-Poly1305 tag — 16 bytes. Associated data включает полный record header.

---

## 7. RS-HS/1: собственный handshake

### 7.1. Криптографическая идея

RS-HS/1 — подписанный ephemeral Diffie–Hellman:

- client и server генерируют свежие X25519 ephemeral keys;
- server подписывает transcript долгосрочным Ed25519 key;
- client проверяет server key из signed manifest;
- handshake keys выводятся из ephemeral X25519 shared secret;
- client identity и signature передаются только после включения handshake encryption;
- client подписывает transcript своим Ed25519 key;
- обе стороны обмениваются Finished MAC;
- application keys выводятся только после полного transcript;
- ephemeral private keys уничтожаются.

Это SIGMA-подобная общая идея, но wire format, transcript, messages и key schedule RekaSerdoba определены самостоятельно. Нельзя утверждать, что свойства SIGMA автоматически переносятся на этот дизайн: нужен отдельный proof/review.

### 7.2. Message types

```text
0x01 CLIENT_HELLO
0x02 SERVER_RETRY
0x03 SERVER_HELLO
0x04 CLIENT_AUTH
0x05 SERVER_FINISH
0x06 CLIENT_FINISH
```

`SERVER_RETRY` — pre-handshake gate и не входит в cryptographic transcript. После Retry client отправляет новый `CLIENT_HELLO` с новым ephemeral key; transcript начинается с принятого сообщения.

### 7.3. CLIENT_HELLO

```text
struct ClientHello {
    u16       protocol_version;      // 0x0001
    u16       cipher_suite;          // 0x0001
    opaque16  handshake_id;          // CSPRNG
    opaque16  client_id;
    opaque32  client_ephemeral_x25519;
    opaque32  client_nonce;
    u64       client_time;
    u16       retry_cookie_len;      // 0 or <= 64
    opaque    retry_cookie;
    u16       extensions_len;        // <= 1024
    Extension extensions[];
}
```

Требования:

- `handshake_id`, ephemeral private key и nonce генерируются заново для каждой попытки после Retry или reconnect;
- X25519 public value декодируется ровно как 32 bytes;
- server отвергает all-zero shared secret после DH;
- отклонение `client_time` по умолчанию не более 300 секунд, но время не является единственной replay-защитой;
- `client_id` выбирает registry entry, но не доказывает identity;
- unknown client обрабатывается с dummy public key и одинаковым внешним поведением;
- суммарный размер message не более 1536 bytes.

Обязательные extensions версии 1 отсутствуют. Возможные будущие:

```text
0x0001 transport_capabilities
0x0002 requested_address_family
0x0003 resumption_ticket
0x0004 resumption_binder
0x0005 post_quantum_keyshare
```

Ни один experimental extension не включается в production suite без отдельной версии спецификации.

### 7.4. Stateless SERVER_RETRY

Server MAY потребовать Retry:

```text
struct ServerRetry {
    u16      protocol_version;
    opaque16 handshake_id;
    u64      expires_at;
    u8       retry_key_id;
    opaque32 cookie_tag;
}
```

```text
cookie_tag = HMAC-SHA256(
    K_retry[retry_key_id],
    "RekaSerdoba/1 retry" ||
    tls_exporter_hash ||
    source_address_prefix ||
    client_id ||
    expires_at
)
```

`source_address_prefix`:

- IPv4: configurable /24 по умолчанию;
- IPv6: configurable /56 по умолчанию.

Широкий prefix переживает некоторые NAT changes, но ослабляет DoS binding. Это operational setting.

После Retry client:

1. проверяет echoed `handshake_id` и expiry;
2. уничтожает старый X25519 private key;
3. создаёт новые `handshake_id`, ephemeral key и nonce;
4. переносит полное opaque Retry cookie в extension;
5. отправляет новый ClientHello.

Server проверяет cookie по exporter, source prefix, client ID и expiry до signature generation и state allocation. Cookie намеренно не привязан к старому ephemeral key, чтобы client безопасно создал новый. Он действует только внутри той же outer session благодаря exporter binding. Retry keys вращаются, например, раз в 10 минут; предыдущий key принимается в коротком overlap.

### 7.5. SERVER_HELLO

```text
struct ServerHelloWithoutSignature {
    u16       protocol_version;
    u16       cipher_suite;
    opaque16  handshake_id;
    opaque32  server_ephemeral_x25519;
    opaque32  server_nonce;
    opaque16  server_key_id;
    u32       server_time;
    u16       extensions_len;
    Extension extensions[];
}

struct ServerHello {
    ServerHelloWithoutSignature fields;
    opaque64 server_signature_ed25519;
}
```

`server_key_id`:

```text
first_16_bytes(
  SHA-256("RekaSerdoba server id" || S_id_pk)
)
```

Пусть:

```text
T1 = transcript after accepted CLIENT_HELLO
SH0 = canonical encoding of ServerHelloWithoutSignature

server_sig_input = SHA-256(
    "RekaSerdoba/1 server signature" ||
    T1 ||
    SHA-256(SH0) ||
    C_id_selector_context
)
```

`C_id_selector_context = client_id || handshake_id`.

```text
server_signature = Ed25519.Sign(S_id_sk, server_sig_input)
```

Client:

1. проверяет version/suite/handshake_id;
2. находит `S_id_pk` в verified manifest;
3. проверяет signature;
4. выполняет X25519;
5. отвергает all-zero result;
6. только затем принимает server как authenticated.

`T2` — transcript после полного `SERVER_HELLO`, включая signature.

### 7.6. Handshake secret

```text
dh = X25519(C_eph_sk, S_eph_pk)

extract_salt = SHA-256(
    "RekaSerdoba/1 handshake extract" ||
    client_nonce ||
    server_nonce ||
    T2
)

handshake_secret = HKDF-Extract(
    salt = extract_salt,
    IKM  = dh
)
```

Это формула полного handshake без resumption. При принятом ticket применяется дополнительное PSK mixing из раздела 13.4.

Derived values:

```text
c_hs_key       = ExpandLabel(handshake_secret, "client handshake key", T2, 32)
s_hs_key       = ExpandLabel(handshake_secret, "server handshake key", T2, 32)
c_hs_iv        = ExpandLabel(handshake_secret, "client handshake iv",  T2, 12)
s_hs_iv        = ExpandLabel(handshake_secret, "server handshake iv",  T2, 12)
c_finished_key = ExpandLabel(handshake_secret, "client finished",      T2, 32)
s_finished_key = ExpandLabel(handshake_secret, "server finished",      T2, 32)
```

### 7.7. Encrypted handshake record

```text
struct EncryptedHandshakeRecord {
    u8  message_type;       // 0x04..0x06
    u8  flags;              // MUST be 0
    u32 sequence_number;
    u16 ciphertext_len;     // includes 16-byte AEAD tag
    opaque ciphertext;
}
```

Каждое direction имеет независимый sequence number, начиная с 0.

```text
AAD = encoded_header || transcript_before_record
nonce = direction_hs_iv XOR left_pad_96(sequence_number)
ciphertext = ChaCha20Poly1305.Seal(direction_hs_key, nonce, plaintext, AAD)
```

Exact encrypted record, а не decrypted object, добавляется в transcript после успешной проверки.

### 7.8. CLIENT_AUTH

Plaintext:

```text
struct ClientAuthPlaintext {
    opaque16 client_id;
    opaque16 client_key_id;
    u32      requested_features;
    u16      requested_mtu;
    u16      extensions_len;
    Extension extensions[];
    opaque64 client_signature_ed25519;
    opaque32 client_finished;
}
```

```text
client_key_id = first_16_bytes(
  SHA-256("RekaSerdoba client key" || C_id_pk)
)

client_sig_input = SHA-256(
    "RekaSerdoba/1 client signature" ||
    T2 ||
    server_signature ||
    S_id_pk ||
    client_id ||
    client_key_id
)

client_signature = Ed25519.Sign(C_id_sk, client_sig_input)

auth_without_finished = all fields through client_signature

client_finished = HMAC-SHA256(
    c_finished_key,
    SHA-256(
      "RekaSerdoba/1 client finished" ||
      T2 ||
      auth_without_finished
    )
)
```

Server после AEAD open:

1. сравнивает client IDs;
2. получает registered `C_id_pk`;
3. проверяет key ID и revocation;
4. проверяет Ed25519 signature;
5. проверяет Finished constant-time;
6. применяет address/quota policy;
7. добавляет encrypted record в transcript как `T3`.

Любая ошибка завершает только authenticated carrier generic close. Подробный reason наружу не отправляется.

### 7.9. SERVER_FINISH

Server формирует параметры:

```text
struct AssignedParameters {
    opaque16 session_id;
    u32      session_lifetime_seconds;
    u16      tunnel_mtu;
    u16      replay_window_size;
    u32      soft_packet_limit;
    u32      soft_time_limit_seconds;
    u8       ipv4_prefix_len;
    opaque4  client_ipv4;
    u8       ipv6_prefix_len;
    opaque16 client_ipv6;
    u8       dns_count;
    Address  dns_servers[];
    u16      route_blob_len;
    opaque   route_blob;
}

struct ServerFinishPlaintext {
    AssignedParameters parameters;
    opaque32 server_finished;
}
```

`session_id` — 16 CSPRNG bytes, уникальные среди активных сессий.

```text
params_hash = SHA-256(canonical AssignedParameters)

server_finished = HMAC-SHA256(
    s_finished_key,
    SHA-256(
      "RekaSerdoba/1 server finished" ||
      T3 ||
      params_hash
    )
)
```

Сообщение шифруется `s_hs_key`, sequence 0. Client:

- проверяет bounds и policy;
- проверяет Finished;
- не устанавливает routes до полной проверки;
- добавляет encrypted record в transcript как `T4`.

### 7.10. CLIENT_FINISH

```text
struct ClientFinishPlaintext {
    opaque16 session_id;
    opaque32 client_confirm;
}

client_confirm = HMAC-SHA256(
    c_finished_key,
    SHA-256(
      "RekaSerdoba/1 client confirm" ||
      T4 ||
      session_id
    )
)
```

Сообщение шифруется `c_hs_key`, sequence 1. Server проверяет и получает `T5`.

Только после этого обе стороны переходят в `ESTABLISHED`.

### 7.11. Handshake state machine

Client:

```text
IDLE
 -> OUTER_CARRIER
 -> GATE_ACCEPTED
 -> SENT_CH
 -> [RETRY -> SENT_CH]
 -> VERIFIED_SH
 -> SENT_CLIENT_AUTH
 -> VERIFIED_SERVER_FINISH
 -> SENT_CLIENT_FINISH
 -> ESTABLISHED
```

Server:

```text
DECOY
 -> GATE_ACCEPTED
 -> RECEIVED_CH
 -> [SENT_RETRY]
 -> SENT_SH
 -> VERIFIED_CLIENT_AUTH
 -> SENT_SERVER_FINISH
 -> VERIFIED_CLIENT_FINISH
 -> ESTABLISHED
```

Любое message вне допустимого state закрывает carrier. Повторное handshake message не переисполняется.

### 7.12. Handshake timeouts и limits

- полный inner handshake: 10 секунд default;
- отдельный flight: 3 секунды;
- максимум один Retry;
- максимум 1536 bytes для clear handshake message;
- максимум 4096 bytes encrypted handshake plaintext;
- максимум 32 одновременных pre-auth handshakes с одного source prefix;
- никаких route/TUN changes до `ESTABLISHED`;
- ephemeral private keys и handshake secrets уничтожаются после application key derivation.

---

## 8. Application key schedule

### 8.1. Master secret

После `T5`:

```text
master_secret = ExpandLabel(
    handshake_secret,
    "master secret",
    T5,
    32
)
```

### 8.2. Независимые roots

```text
epoch_secret[0] = ExpandLabel(master_secret, "epoch root", T5, 32)
migration_secret  = ExpandLabel(master_secret, "migration", T5, 32)
resumption_secret = ExpandLabel(master_secret, "resumption", T5, 32)
exporter_secret   = ExpandLabel(master_secret, "exporter", T5, 32)
```

### 8.3. Epoch 0 keys

Для каждого direction:

```text
c2s_data_key[0] = ExpandLabel(epoch_secret[0], "data c2s key", session_id || u32(0), 32)
s2c_data_key[0] = ExpandLabel(epoch_secret[0], "data s2c key", session_id || u32(0), 32)
c2s_data_iv[0]  = ExpandLabel(epoch_secret[0], "data c2s iv",  session_id || u32(0), 12)
s2c_data_iv[0]  = ExpandLabel(epoch_secret[0], "data s2c iv",  session_id || u32(0), 12)

c2s_ctrl_key[0] = ExpandLabel(epoch_secret[0], "control c2s key", session_id || u32(0), 32)
s2c_ctrl_key[0] = ExpandLabel(epoch_secret[0], "control s2c key", session_id || u32(0), 32)
c2s_ctrl_iv[0]  = ExpandLabel(epoch_secret[0], "control c2s iv",  session_id || u32(0), 12)
s2c_ctrl_iv[0]  = ExpandLabel(epoch_secret[0], "control s2c iv",  session_id || u32(0), 12)
```

Handshake keys MUST быть удалены после подтверждения `CLIENT_FINISH` и установки epoch 0.

### 8.4. Security rationale и границы

- Ephemeral X25519 даёт PFS при удалении private values.
- Ed25519 signatures привязывают ephemeral exchange к identities.
- Server signature проверяется до отправки client identity внутри inner encryption.
- Client signature и Finished подтверждают identity и possession DH secret.
- Transcript предотвращает перестановку и downgrade внутри определённого encoding.
- Разные labels разделяют ключи.
- Пятисообщенческий handshake выбран ради явного mutual key confirmation, а не минимальной latency.

Это rationale, не security proof.

---

## 9. RS-DP/1: data plane

### 9.1. Data record header

```text
struct DataRecordHeader {
    u8       version_flags;
    opaque16 session_id;
    u32      epoch;
    u64      packet_number;
    u16      ciphertext_len;
}
```

`version_flags`:

```text
bits 7..4: version = 1
bit  3:    CONTROL = 0 for data record
bit  2:    KEY_PHASE hint
bit  1:    PADDED hint
bit  0:    reserved = 0
```

Header length — 31 bytes. `ciphertext_len` включает 16-byte tag и MUST быть в диапазоне 16–4096.

### 9.2. Data encryption

```text
AAD = full encoded DataRecordHeader
nonce = data_iv[epoch] XOR left_pad_96(packet_number)
ciphertext = ChaCha20Poly1305.Seal(
    data_key[epoch],
    nonce,
    frames_plaintext,
    AAD
)
```

Header защищён как AAD: изменение session, epoch, number или length приводит к AEAD failure.

### 9.3. Frame encoding

```text
struct Frame {
    u8  frame_type;
    u8  frame_flags;
    u16 frame_len;
    opaque body[frame_len];
}
```

Frames concatenated до конца plaintext.

Types:

```text
0x00 PADDING
0x01 IPV4_PACKET
0x02 IPV6_PACKET
0x03 IP_FRAGMENT
0x04 DATAGRAM_KEEPALIVE
0x05 PATH_PROBE
0x06 PATH_PROBE_REPLY
```

Unknown non-critical `frame_type < 0x80` игнорируется после bounds validation. Unknown critical type `>= 0x80` закрывает session.

### 9.4. IP packet frames

`IPV4_PACKET` body — точный IPv4 packet с header.<br>
`IPV6_PACKET` body — точный IPv6 packet.

Receiver MUST:

- проверить минимальную header length;
- проверить version nibble;
- проверить declared IP total/payload length;
- запретить packet длиннее negotiated tunnel MTU, если fragmentation не включена;
- проверить source address против client policy;
- не исправлять silently malformed packet;
- не декрементировать inner TTL внутри point-to-point tunnel до передачи routing stack; это делает ОС при дальнейшем forwarding.

### 9.5. Fragmentation

Fragmentation — optional negotiated feature. Предпочтительно корректно выбрать TUN MTU.

```text
struct FragmentBody {
    u32 packet_id;
    u16 total_len;
    u16 offset;
    u16 fragment_len;
    opaque fragment[fragment_len];
}
```

Rules:

- `total_len <= 65535`;
- ranges не перекрываются;
- offset + length <= total;
- один `packet_id` относится к одному direction и epoch;
- максимум 64 concurrent reassemblies на client;
- максимум 8 MiB memory;
- timeout 3 секунды;
- duplicate identical fragment игнорируется;
- conflicting overlap уничтожает reassembly;
- complete packet проходит обычную IP validation.

Fragment frame сам защищён AEAD. Это не отменяет memory DoS limits.

### 9.6. Padding

`PADDING` body — CSPRNG bytes. Нулевые padding bytes не запрещены, но постоянный zero pattern внутри ciphertext не виден напрямую.

Padding policy:

- задаётся signed cover profile;
- имеет overhead budget;
- не задерживает interactive packet более configured maximum;
- не использует один постоянный target size;
- не считается криптографической защитой.

### 9.7. Packet number

Каждое direction и epoch имеет отдельный монотонный `u64`.

- sender начинает с 0;
- number выделяется атомарно до encryption;
- после crash session не восстанавливается с теми же keys;
- retransmission inner record запрещена с тем же nonce;
- если carrier требует повторной передачи, он повторяет уже готовый ciphertext byte-for-byte только в пределах transport semantics; receiver anti-replay примет его максимум один раз;
- новое шифрование того же plaintext получает новый number.

### 9.8. Anti-replay window

Receiver поддерживает bitmap window по [идее RFC 6479](https://www.rfc-editor.org/info/rfc6479/).

Default `W = 4096`, разрешённый диапазон 256–16384.

Пусть `N` — incoming packet number, `H` — highest authenticated:

1. если `N + W <= H`, packet слишком старый — drop до decryption MAY применяться только как preliminary check;
2. если `N` внутри window и bit уже установлен — duplicate drop;
3. иначе выполнить AEAD open;
4. только после успешного authentication сдвинуть window/поставить bit;
5. failed AEAD никогда не меняет replay state.

Pre-check не заменяет authentication: attacker может отправить большое `N`, но window двигается только после valid tag.

### 9.9. Data delivery semantics

В стабильной реализации H3 carrier data records идут через надёжный двунаправленный WebTransport stream. Это исключает накопление незавершённых IP-fragment assemblies при потере QUIC datagrams и делает поведение одинаково предсказуемым во всех трёх carriers.

На H3/H2/WSS carrier records доставляются reliably/ordered, что может создавать head-of-line blocking. Поэтому:

- bounded queues;
- no application retransmit;
- backpressure;
- drop newest/flow policy только по явной конфигурации;
- H2/WSS — доступность, а не оптимальная производительность.

---

## 10. RS-CP/1: encrypted control plane

### 10.1. Control record

Control использует reliable ordered stream каждого carrier, но имеет собственное AEAD и sequence.

```text
struct ControlRecordHeader {
    u8       version_flags;    // version=1, CONTROL=1
    opaque16 session_id;
    u32      epoch;
    u64      sequence_number;
    u16      ciphertext_len;
}
```

Encryption идентично data record, но применяются `ctrl_key/ctrl_iv`. Data и control sequence spaces независимы.

Control receiver также имеет replay window, потому что во время migration два carriers могут кратко доставлять records с разным порядком.

### 10.2. Control frame format

Внутри control plaintext:

```text
struct ControlFrame {
    u8  type;
    u8  flags;
    u16 length;
    opaque body[length];
}
```

Types:

```text
0x01 SETTINGS
0x02 PING
0x03 PONG
0x04 KEY_UPDATE_REQUEST
0x05 KEY_UPDATE_INIT
0x06 KEY_UPDATE_ACK
0x07 KEY_UPDATE_COMMIT
0x08 KEY_UPDATE_DONE
0x09 FULL_REKEY_INIT
0x0A FULL_REKEY_REPLY
0x0B FULL_REKEY_CONFIRM
0x0C PATH_CHALLENGE
0x0D PATH_RESPONSE
0x0E MTU_UPDATE
0x0F ROUTE_UPDATE
0x10 SESSION_TICKET
0x11 TICKET_REVOKE
0x12 CLOSE
0x13 ERROR
```

`ERROR` разрешён только после mutual authentication. До этого внешнее поведение generic.

### 10.3. Control transcript

Для security-critical control:

```text
CT0 = SHA-256("RekaSerdoba/1 control transcript" || T5 || session_id)
CTn = SHA-256(CT(n-1) || exact_authenticated_control_record)
```

Обычные PING/PONG и telemetry frames MAY не включаться в CT. Rekey, migration, route update и ticket включаются обязательно.

---

## 11. Routine key update

### 11.1. Зачем два вида rekey

Routine update:

- быстро меняет symmetric keys;
- ограничивает число records под одним nonce space;
- защищает прошлые epochs после удаления старого secret;
- не восстанавливает будущую секретность, если attacker уже знает текущий `epoch_secret`.

Full rekey:

- добавляет новый X25519 entropy;
- подписывает новый exchange identity keys;
- способен восстановить future secrecy после компрометации traffic key, если identity keys и новые ephemeral private values не украдены.

### 11.2. Кто инициирует

В версии 1 routine update инициирует client. Server отправляет `KEY_UPDATE_REQUEST`, после чего client начинает процедуру. Это исключает concurrent update collision.

Triggers по умолчанию:

- 10 минут;
- `2^20` data records;
- 1 GiB plaintext;
- что наступит раньше.

Hard limit:

- `2^32` records на epoch запрещены, несмотря на `u64` packet number;
- при невозможности rekey session закрывается до hard limit.

### 11.3. KEY_UPDATE_INIT

```text
struct KeyUpdateInit {
    u32      current_epoch;
    u32      next_epoch;       // current + 1
    opaque32 update_nonce;
    opaque32 transcript_tag;
}

transcript_tag = HMAC-SHA256(
    epoch_secret[current],
    "RekaSerdoba/1 epoch update" ||
    session_id ||
    current_epoch ||
    next_epoch ||
    update_nonce ||
    CT
)
```

Frame шифруется старым client→server control key.

### 11.4. Derivation pending epoch

Обе стороны:

```text
update_context = SHA-256(
    "RekaSerdoba/1 epoch update" ||
    session_id ||
    current_epoch ||
    next_epoch ||
    update_nonce ||
    CT
)

epoch_secret[next] = HKDF-Extract(
    salt = epoch_secret[current],
    IKM  = update_context
)
```

Keys/IV выводятся из нового secret по формулам раздела 8.3.

### 11.5. ACK, COMMIT, DONE

```text
confirm_key = ExpandLabel(
    epoch_secret[next],
    "epoch confirmation",
    session_id || next_epoch,
    32
)

ack = HMAC-SHA256(
    confirm_key,
    "server ack" || update_context
)
```

1. Server отправляет `KEY_UPDATE_ACK(next_epoch, ack)` под старым control key.
2. Client проверяет ACK.
3. Client начинает новый transmit epoch с sequence/packet number 0.
4. Client отправляет `KEY_UPDATE_COMMIT` под новым control key.
5. Server проверяет и переключает transmit.
6. Server отправляет `KEY_UPDATE_DONE` под новым key.
7. Стороны удаляют старый secret после grace.

Grace:

- максимум 3 секунды;
- максимум 128 старых records;
- старый epoch принимается только existing replay window;
- после grace старые keys zeroized best effort.

### 11.6. Crash safety

Session state с packet numbers не сохраняется на диск. После process crash выполняется новый handshake. Нельзя загружать старый epoch secret с обнулённым counter.

---

## 12. Full signed ephemeral rekey

### 12.1. Triggers

Default:

- каждые 30 минут;
- каждые 4 GiB;
- после подозрения на memory exposure;
- после migration через новый ingress;
- по signed server policy.

### 12.2. FULL_REKEY_INIT

Client создаёт:

```text
rekey_id:     16 CSPRNG bytes
C_rekey_eph:  fresh X25519 public key
target_epoch: current + 1

rekey_client_sig_input = SHA-256(
    "RekaSerdoba/1 full rekey client" ||
    session_id ||
    current_epoch ||
    target_epoch ||
    rekey_id ||
    C_rekey_eph ||
    CT
)

client_rekey_signature =
  Ed25519.Sign(C_id_sk, rekey_client_sig_input)
```

Frame:

```text
current_epoch u32
target_epoch  u32
rekey_id      opaque16
C_rekey_eph   opaque32
signature     opaque64
```

Он шифруется текущим control key.

### 12.3. FULL_REKEY_REPLY

Server проверяет session/epoch/signature и создаёт fresh `S_rekey_eph`.

```text
server_rekey_sig_input = SHA-256(
    "RekaSerdoba/1 full rekey server" ||
    session_id ||
    current_epoch ||
    target_epoch ||
    rekey_id ||
    C_rekey_eph ||
    S_rekey_eph ||
    CT_after_init
)

server_rekey_signature =
  Ed25519.Sign(S_id_sk, server_rekey_sig_input)
```

### 12.4. New root

```text
rekey_dh = X25519(C_rekey_sk, S_rekey_pk)
```

All-zero запрещён.

```text
rekey_context = SHA-256(
    "RekaSerdoba/1 full rekey" ||
    session_id ||
    current_epoch ||
    target_epoch ||
    rekey_id ||
    C_rekey_eph ||
    S_rekey_eph ||
    client_rekey_signature ||
    server_rekey_signature ||
    CT
)

epoch_secret[target] = HKDF-Extract(
    salt = epoch_secret[current],
    IKM  = rekey_dh || rekey_context
)
```

`rekey_dh` имеет фиксированные 32 bytes, `rekey_context` — 32, поэтому concatenation однозначна.

### 12.5. Confirm

Client отправляет `FULL_REKEY_CONFIRM` под target control key:

```text
confirm = HMAC-SHA256(
    ExpandLabel(epoch_secret[target], "full rekey confirm", rekey_context, 32),
    "client confirm" || rekey_context
)
```

Server отвечает `KEY_UPDATE_DONE` под target key. После grace обе стороны:

- уничтожают old epoch secret;
- уничтожают rekey ephemeral private keys;
- обновляют CT;
- не принимают повторный `rekey_id`.

### 12.6. Compromise discussion

Если attacker знает старый epoch secret, он читает encrypted rekey messages, но видит только X25519 public keys. Он не может подменить их без Ed25519 signatures. Поэтому passive или active attacker с traffic keys, но без identity keys, не должен вычислить new DH secret.

Это ожидаемое свойство конструкции, не формально доказанный результат.

---

## 13. Session resumption

### 13.1. Политика версии 1

0-RTT tunnel data запрещены. Resumption не пропускает client signature и не сокращает mutual authentication в первой audited версии. Его задачи:

- безопасная выдача короткоживущего PSK;
- дополнительное смешивание secret;
- подготовка к будущей оптимизации;
- отзыв ticket отдельно от identity.

Реализация MAY полностью отключить tickets.

### 13.2. Ticket plaintext

```text
struct TicketPlaintext {
    opaque16 ticket_id;
    opaque16 client_id;
    opaque16 server_key_id;
    u64      issued_at;
    u64      expires_at;
    opaque32 resumption_psk;
    opaque32 policy_hash;
    u32      max_uses;          // v1 MUST be 1
}
```

Server шифрует ticket ChaCha20-Poly1305:

```text
ticket = ticket_key_id:u8 ||
         nonce:opaque12 ||
         AEAD_Seal(
           K_ticket[key_id],
           nonce,
           TicketPlaintext,
           "RekaSerdoba/1 ticket" || server_key_id
         )
```

Ticket keys rotating, хранятся только server side. Client получает отдельно:

- opaque ticket;
- `resumption_psk`;
- expiry.

Оба передаются внутри encrypted control.

### 13.3. Binder

ClientHello extensions содержат ticket и:

```text
binder = HMAC-SHA256(
    resumption_psk,
    SHA-256(
      "RekaSerdoba/1 resumption binder" ||
      canonical ClientHello without binder
    )
)
```

Server проверяет:

- ticket AEAD;
- expiry;
- client/server IDs;
- single-use replay database;
- policy hash;
- binder.

`SERVER_HELLO` signed extension сообщает accepted/rejected. Client не угадывает состояние.

### 13.4. PSK mixing

Раздел 7.6 расширяется:

```text
psk_input =
  accepted resumption_psk
  OR 32 zero bytes

pre_secret = HKDF-Extract(
    salt = extract_salt,
    IKM  = psk_input
)

handshake_secret = HKDF-Extract(
    salt = pre_secret,
    IKM  = dh
)
```

Даже при PSK остаётся fresh ephemeral DH и PFS. При rejection обе стороны используют zeros. Signed ServerHello защищает downgrade результата.

### 13.5. Ticket replay

Ticket одноразовый. Server помечает `ticket_id` использованным только после успешного `CLIENT_FINISH`; параллельные attempts резервируют ID на короткое время. Failure до finish снимает reservation с rate limit.

---

## 14. Carrier admission

### 14.1. Задача

До RS-HS server должен:

- выглядеть как обычный H2/H3 website;
- дешёво отбрасывать scanner;
- не раскрывать valid client IDs;
- не запускать X25519/Ed25519 для random traffic;
- привязать request к конкретной outer TLS/QUIC session;
- ограничить replay.

### 14.2. Gate token

Outer TLS exporter:

```text
outer_exporter = TLS-Exporter(
    label   = "EXPORTER-RekaSerdoba-gate",
    context = SHA-256(authority || 0x00 || path),
    length  = 32
)
```

Token:

```text
client_id: 16 bytes
unix_time:  8 bytes
nonce:     16 bytes
mac:       32 bytes
```

```text
mac = HMAC-SHA256(
    K_gate,
    "RekaSerdoba/1 gate" ||
    outer_exporter ||
    method || 0x00 ||
    authority || 0x00 ||
    path || 0x00 ||
    client_id ||
    unix_time ||
    nonce
)
```

72-byte token кодируется base64url и помещается в `Authorization: Bearer` внутри TLS.

Canonicalization:

- uppercase method;
- lower-case DNS A-label без trailing dot;
- explicit port;
- exact path из manifest;
- server сравнивает exact values.

### 14.3. Server checks

1. exact token length;
2. time window ±90 секунд;
3. client selector lookup или dummy key;
4. HMAC constant-time;
5. replay cache `(client_id, nonce)` минимум 180 секунд;
6. per-client/source rate limit;
7. только затем upgrade к RS-HS.

Invalid request передаётся реальному decoy router. Нельзя возвращать уникальный status, body, delay или TLS alert.

### 14.4. Gate не является user authentication

`K_gate` — capability попасть на handshake. Client authentication выполняет только Ed25519 signature в `CLIENT_AUTH`.

---

## 15. Carrier bindings

### 15.1. Общий interface

```rust
#[async_trait]
pub trait Carrier {
    async fn connect(&mut self, endpoint: &Endpoint, gate: &GateCredential)
        -> Result<CarrierSession>;
    async fn send_reliable(&self, record: Bytes) -> Result<()>;
    async fn recv_reliable(&self) -> Result<Bytes>;
    fn delivery(&self) -> DeliveryMode;
    fn health(&self) -> CarrierHealth;
    async fn close(&self);
}
```

Handshake и control всегда идут reliable. Data:

- H3 — reliable WebTransport stream;
- H2/WSS — reliable messages.

### 15.2. H3 carrier

Используются:

- QUIC;
- HTTP/3;
- Extended CONNECT;
- WebTransport bidirectional streams;
- стандартные ALPN и TLS 1.3;
- настоящий H3 decoy.

RekaSerdoba record имеет length-prefixed framing внутри WebTransport stream. Сервер не является open proxy: path связан с локальным RS endpoint.

Преимущества:

- нет TCP head-of-line между независимыми QUIC streams;
- NAT rebinding;
- QUIC reliability и flow control;
- стандартный массовый transport.

Ограничения:

- UDP/443 можно нарушить;
- QUIC Initial наблюдаем;
- implementation fingerprint остаётся;
- ECH не скрывает IP.

### 15.3. H2 carrier

- TLS/TCP 443;
- ALPN `h2`;
- один authenticated Extended CONNECT stream;
- reliable record capsules;
- handshake/control/data multiplexed с type;
- bounded queue.

H2 не имитирует браузер полностью: долгий двунаправленный stream может классифицироваться. Он fallback.

### 15.4. WSS carrier

- standard HTTPS WebSocket;
- binary messages;
- один RekaSerdoba record на WebSocket message;
- compression disabled;
- 4096/negotiated maximum;
- ping/pong только carrier health;
- real decoy behavior на invalid gate.

### 15.5. Никаких custom outer признаков

Запрещены:

- `reka/1` ALPN;
- cleartext magic;
- отдельный публичный port;
- фальшивый SNI чужого сайта;
- snapshot QUIC вместо QUIC;
- self-signed outer certificate;
- отключение hostname verification.

### 15.6. Same frontend rule

Tunnel и decoy используют:

- один IP:port;
- один certificate chain;
- один TLS/QUIC stack;
- один ALPN set;
- одинаковые HTTP defaults;
- нормальные error paths.

Если decoy и tunnel завершают TLS разными библиотеками, это должно считаться fingerprint regression.

---

## 16. Session migration

### 16.1. Migration token

При активной session client открывает новый carrier и использует:

```text
session_id: 16
timestamp:   8
nonce:      16
mac:        32

mac = HMAC-SHA256(
    migration_secret,
    "RekaSerdoba/1 migration gate" ||
    new_outer_exporter ||
    session_id ||
    timestamp ||
    nonce ||
    endpoint_id
)
```

Server проверяет token и replay cache без нового identity handshake.

### 16.2. Path validation

Server создаёт:

```text
carrier_id: opaque16
challenge:  opaque32
```

Отправляет `PATH_CHALLENGE` на новом reliable channel под текущим control key. Client отвечает `PATH_RESPONSE`:

```text
response = HMAC-SHA256(
    migration_secret,
    "RekaSerdoba/1 path response" ||
    session_id ||
    carrier_id ||
    challenge ||
    CT
)
```

Только после valid response новый carrier может нести data.

### 16.3. State machine

```text
ACTIVE(old)
 -> DIAL(new)
 -> MIGRATION_GATE_OK
 -> PATH_CHALLENGE
 -> PATH_VALIDATED
 -> SWITCH_TX
 -> DRAIN(old)
 -> ACTIVE(new)
```

Правила:

- packet numbers глобальны для session/epoch, не для carrier;
- нельзя сбрасывать counter при migration;
- data не дублируется постоянно;
- old carrier принимает in-flight records в короткий drain;
- late old packet проходит обычный replay window;
- control sequence также глобален.

### 16.4. Когда нужен новый handshake

Полный handshake обязателен, если:

- migration token invalid/expired;
- server потерял session state;
- client process перезапущен;
- epoch keys не синхронизированы;
- manifest требует другой server identity;
- session lifetime истёк;
- есть подозрение на state rollback.

---

## 17. Signed manifest и onboarding

### 17.1. Разделение public и secret

Public manifest:

- endpoint;
- server identity keys;
- carriers;
- validity;
- update policy;
- cover profiles;
- route limits.

Secret device record:

- client identity private key;
- `K_gate`;
- optional resumption state;
- local profile ID.

Secrets никогда не публикуются в update manifest.

### 17.2. Public manifest

Используется deterministic CBOR и `COSE_Sign1`/Ed25519:

- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html);
- [RFC 9052: COSE](https://www.rfc-editor.org/rfc/rfc9052.html).

CDDL:

```cddl
reka-manifest = {
  1: 1,                         ; schema
  2: bstr .size 16,             ; profile_id
  3: uint,                      ; monotonic sequence
  4: uint,                      ; not_before
  5: uint,                      ; expires
  6: 1,                         ; RS protocol major
  7: 1,                         ; mandatory suite
  8: [1* server-identity],
  9: [1* endpoint],
  10: tunnel-policy,
  11: update-policy,
  ? 12: [* tls-pin],
  ? 13: bstr .size 32           ; next manifest signing key
}

server-identity = {
  1: bstr .size 16,             ; server_key_id
  2: bstr .size 32,             ; Ed25519 public key
  3: uint,                      ; not_before
  4: uint                       ; expires
}

endpoint = {
  1: uint,                      ; endpoint_id
  2: tstr,                      ; authority
  3: uint,                      ; port
  4: bstr .size 16,             ; server_key_id
  5: [1* carrier],
  ? 6: [* tstr]                 ; signed IP literals
}

carrier = {
  1: uint,                      ; 1 H3, 2 H2, 3 WSS
  2: tstr,                      ; exact path/template
  3: uint,                      ; priority
  4: uint,                      ; connect timeout ms
  5: uint,                      ; max outer record
  6: uint,                      ; cover_profile_id
  7: padding-policy
}

tunnel-policy = {
  1: uint,                      ; initial MTU
  2: bool,                      ; IPv4
  3: bool,                      ; IPv6
  4: bool,                      ; kill switch required
  5: [* tstr],                  ; maximum allowed routes
  6: uint,                      ; session lifetime cap
  7: uint                       ; fallback cooldown
}

update-policy = {
  1: tstr,
  2: uint,
  3: bstr .size 32
}

tls-pin = [ bstr .size 32, uint, uint ]
padding-policy = { 1: uint, 2: [* [uint, uint]], 3: uint }
```

### 17.3. Device record

```cddl
device-record = {
  1: bstr .size 16,             ; profile_id
  2: bstr .size 16,             ; client_id
  3: bstr .size 32,             ; Ed25519 private seed
  4: bstr .size 32,             ; K_gate
  5: uint,                      ; created_at
  ? 6: ticket-state,
  ? 7: bstr                     ; recovery metadata
}
```

На Windows record шифруется DPAPI и доступен только service identity. Private key не передаётся UI.

### 17.4. Verification

Client принимает manifest, только если:

1. COSE signature верна;
2. root signing key доверен локально;
3. profile ID совпадает;
4. sequence строго больше сохранённого;
5. validity подходит;
6. schema/protocol/suite поддерживаются;
7. server identity lifetime покрывает endpoint;
8. URI и sizes проходят bounds;
9. root rotation подписана старым key с overlap.

Даже подписанный manifest с меньшим sequence отвергается.

### 17.5. TLS identity

Outer TLS использует обычный WebPKI certificate и hostname verification. Единственный вечный SPKI pin нежелателен: certificate rotation превратится в outage. Если pins нужны, manifest содержит несколько overlapping pins.

Inner server identity — Ed25519 key из manifest. Поэтому компрометация внешнего TLS terminator не раскрывает RS-DP plaintext и не позволяет подделать RS-HS без `S_id_sk`.

### 17.6. Onboarding

Для личного deployment:

1. client локально генерирует `C_id_sk/C_id_pk`;
2. admin получает только `C_id_pk`;
3. server registry создаёт client policy;
4. admin генерирует `K_gate`;
5. client получает signed public manifest + encrypted device bundle;
6. client показывает fingerprint profile/signing/server keys;
7. server никогда не получает client private key.

QR-code допустим только для небольшого encrypted bootstrap bundle. Он не должен содержать plaintext private key без парольной защиты.

### 17.7. Revocation

Независимые действия:

- revoke `K_gate`: запретить новый handshake;
- revoke `C_id_pk`: запретить cryptographic authentication;
- revoke ticket: запретить resumption;
- удалить active sessions;
- rotate server identity через signed manifest;
- rotate manifest signing root отдельно.

---

## 18. MTU, packet size и traffic morphology

### 18.1. Overhead

Минимальный inner overhead одного IP packet:

```text
RS data header      31 bytes
Frame header         4 bytes
AEAD tag            16 bytes
Total               51 bytes
```

К этому добавляются HTTP/QUIC/TLS и outer IP/UDP/TCP headers.

Начальный TUN MTU — 1280. Для H3 implementation вычисляет:

```text
max_inner =
  path_mtu
  - outer headers
  - carrier framing
  - 51
```

Если negotiated 1280 inner packet не помещается, используются:

- корректный ICMP Packet Too Big;
- DPLPMTUD;
- RS fragmentation, если negotiated;
- более подходящий carrier.

Нельзя полагаться на outer IP fragmentation.

### 18.2. Padding buckets

Cover profile задаёт:

```text
bucket_size, weight
overhead_budget_percent
max_added_delay_ms
minimum_payload_size
```

Алгоритм выбирает допустимый bucket CSPRNG с учётом фактической record length. Если budget исчерпан, padding отключается.

### 18.3. Batching

H3 MAY объединять несколько небольших IP frames в один RS record:

- максимум 8 frames;
- максимум 2 ms ожидания;
- packet отправляется при достижении заданного record budget;
- latency-sensitive frames без ожидания;
- record остаётся одним AEAD plaintext.

Batching не применяется к handshake и security-critical control.

### 18.4. Почему случайность не равна маскировке

Одинаковый генератор случайных размеров создаёт собственное статистическое распределение. Поэтому:

- profile строится на измерениях;
- разные cohorts могут иметь разные profiles;
- CI сравнивает flow shape;
- padding оценивается вместе с latency/overhead;
- не заявляется «неотличимость».

---

## 19. Transport policy и диагностика

### 19.1. Error classes

```text
DNS_NXDOMAIN
DNS_TIMEOUT
NO_ROUTE
TCP_TIMEOUT
TCP_RESET
UDP_NO_RESPONSE
TLS_CERTIFICATE
TLS_HANDSHAKE
QUIC_VERSION
QUIC_HANDSHAKE
HTTP_STATUS
GATE_FAILED_LOCAL_HYPOTHESIS
RS_HANDSHAKE_TIMEOUT
RS_SERVER_SIGNATURE
RS_CLIENT_REJECTED_LOCAL_HYPOTHESIS
RS_FINISHED
RS_DATA_STALL
RS_REPLAY_EXCESS
PMTU_FAILURE
LOCAL_ROUTE
LOCAL_WFP
LOCAL_TUN
```

Server не обязан раскрывать gate/auth reason. Часть client codes — локальные hypotheses.

### 19.2. Network identity

```text
network_id = HMAC-SHA256(
  device_local_key,
  interface_type ||
  address_family ||
  gateway_prefix ||
  captive_state
)
```

SSID, MAC и public IP не пишутся в telemetry.

### 19.3. Selection

1. недавно успешный carrier для network;
2. иначе H3;
3. H2;
4. WSS;
5. следующий endpoint.

Retries:

- exponential backoff;
- jitter;
- endpoint cooldown;
- no connection storm;
- signed manifest ограничивает допустимые carriers;
- сеть не может прислать unauthenticated downgrade command.

### 19.4. DPI diagnosis

Один failure не объявляется блокировкой. Hypothesis повышает confidence, если:

- обычный decoy H3 работает, а gate/RS path нет;
- H3 fails на нескольких endpoint, H2 succeeds;
- TLS completes, затем reset после стабильного byte count;
- failure повторяется в одной AS/network, но не другой;
- pcap показывает consistent drop point;
- certificate/DNS/local errors исключены.

---

## 20. Windows client

### 20.1. Processes

```text
reka-ui.exe       unprivileged UI
reka-service.exe  privileged network/crypto service
reka-updater.exe  signed updater
```

Named-pipe IPC:

- explicit ACL;
- versioned messages;
- no arbitrary filesystem paths;
- caller identity validation;
- bounded input.

### 20.2. Wintun

[Wintun](https://www.wintun.net/) предоставляет L3 adapter. Service:

- создаёт adapter;
- назначает negotiated IPv4/IPv6;
- ставит MTU;
- читает IP packets;
- формирует RS frames/records;
- decrypts incoming records;
- пишет validated IP packets обратно.

### 20.3. Route transaction

Порядок:

1. snapshot network state;
2. install WFP block policy;
3. allow endpoint/bootstrap exceptions;
4. create Wintun;
5. set IP/MTU;
6. set tunnel DNS;
7. add routes;
8. establish carrier;
9. complete RS-HS;
10. mark connected.

До `CLIENT_FINISH` server parameters не применяются.

### 20.4. Kill switch через WFP

Routes не являются kill switch. WFP rules:

- allow loopback;
- allow DHCP/NDP;
- allow service к signed endpoint;
- allow approved bootstrap DNS;
- block other egress outside Wintun;
- cover IPv4/IPv6/DNS;
- persist при UI crash;
- retain secure state при service failure;
- elevated recovery tool снимает policy.

### 20.5. DNS

- resolver внутри tunnel;
- external UDP/TCP 53 и 853 block;
- IPv6 resolver included;
- cache isolation при network change;
- no query logging;
- signed IP literals для bootstrap;
- TLS hostname всё равно проверяется.

### 20.6. Key storage

- Ed25519 private seed, `K_gate`, tickets — DPAPI;
- no command line/environment;
- UI не читает secrets;
- crash dumps restricted;
- logs redact;
- explicit protected export;
- zeroize library types where available.

### 20.7. Lifecycle tests

- Ethernet/Wi-Fi;
- multiple NIC;
- hotspot;
- sleep/hibernate;
- Fast Startup;
- captive portal;
- IPv6-only;
- service crash;
- update;
- network switch;
- clock skew;
- adapter recreation.

---

## 21. Linux server

### 21.1. Components

```text
reka-edge       TLS/H2/H3/WSS + decoy + gate
reka-core       RS-HS/RS-DP/RS-CP
reka-net        TUN + route/nftables helper
reka-admin      client registry and manifest signing workflow
```

MVP MAY combine edge/core, но admin signing key остаётся offline.

### 21.2. Privilege separation

- edge/core unprivileged;
- minimal helper owns CAP_NET_ADMIN;
- Unix socket with peer credentials;
- no shell commands from network input;
- systemd sandbox;
- read-only filesystem where possible;
- secrets separate from decoy content.

### 21.3. TUN and forwarding

Linux [TUN/TAP documentation](https://docs.kernel.org/networking/tuntap.html) определяет userspace L3 interface.

Server:

- пишет decrypted validated packet в TUN;
- читает return packet;
- maps destination tunnel IP to session;
- encrypts correct direction;
- применяет source/destination policy;
- не позволяет spoof другого client address.

### 21.4. nftables

- input default drop;
- 443/TCP and 443/UDP;
- admin only management network;
- forwarding only TUN;
- established return;
- IPv4 NAT if needed;
- explicit IPv6 policy;
- no access to management plane;
- rate limits;
- antispoof.

### 21.5. Client registry

Для каждого client:

- `client_id`;
- `C_id_pk`;
- tunnel addresses;
- allowed routes;
- `K_gate` hash/secure value;
- revocation;
- active session limit;
- bandwidth/quota;
- last ticket IDs;
- no user browsing destinations.

### 21.6. Decoy

На том же frontend:

- real HTML routes;
- CSS/JS/images;
- 404/HEAD/range behavior;
- H2 and H3;
- normal cache headers;
- no copied brand;
- no static universal probe page.

### 21.7. Logs

Допустимо:

- carrier/error counters;
- handshake stage aggregate;
- CPU/memory/queue;
- bytes by session bucket;
- replay/rate-limit count;
- manifest version.

Не хранить:

- inner destinations;
- DNS queries;
- IP payload;
- private keys;
- full auth tokens;
- decrypted control contents без explicit debug.

---

## 22. Анализ безопасности

Этот раздел не является доказательством безопасности. Он фиксирует свойства, которые должна обеспечивать реализация, и показывает, где именно находятся предположения.

### 22.1. Что аутентифицируется

После успешного `CLIENT_FINISH` обе стороны должны знать следующее:

- клиент проверил подпись долгосрочного ключа сервера над свежим transcript;
- сервер проверил подпись зарегистрированного долгосрочного ключа клиента;
- обе стороны доказали владение одним и тем же handshake secret через Finished MAC;
- session ID, выбранный suite, оба ephemeral key share, параметры туннеля и весь порядок сообщений включены в transcript;
- ключи направлений различны;
- ключи data plane и control plane различны;
- ключи разных epoch различны.

Входной `gate_token` и Retry cookie **не являются** доказательством личности. Это только ранняя фильтрация и защита от части DoS-нагрузки.

### 22.2. Forward secrecy

Базовый handshake использует свежую пару X25519 с каждой стороны. Если спустя время утечёт Ed25519-ключ клиента или сервера, записанный ранее трафик не должен расшифровываться, если:

1. ephemeral private keys действительно удалены;
2. генератор случайных чисел не был скомпрометирован;
3. X25519, HKDF-SHA-256 и ChaCha20-Poly1305 остаются стойкими;
4. память процесса не была снята во время сессии.

Обычный симметричный `KEY_UPDATE` лишь развивает старый секрет и не восстанавливает безопасность после его утечки. Для восстановления применяется полный signed ephemeral rekey с новым DH.

### 22.3. Компрометация ключей

| Утечка | Последствие | Что не должно следовать автоматически |
|---|---|---|
| `K_gate` одного устройства | Возможность пройти ранний admission для этого `client_id` | Подделка handshake без Ed25519-ключа |
| Ed25519-ключ клиента | Имперсонация этого клиента до отзыва | Расшифровка старых сессий |
| Ed25519-ключ сервера | Имперсонация сервера для будущих подключений | Расшифровка старых сессий |
| Текущий epoch secret | Чтение/подделка текущего epoch | Старые epoch после их удаления |
| Ticket encryption key | Раскрытие/подделка tickets соответствующей ротации | Аутентификация без клиентской подписи, если сервер всё равно требует её |
| Manifest signing key | Распространение вредной конфигурации | Подделка внутреннего handshake server key |
| Внешний TLS private key | Имперсонация carrier frontend | Расшифровка внутреннего RS-DP без прохождения RS-HS |

Manifest key, внутренний identity key, TLS key и ticket key должны быть разными и храниться в разных контурах.

### 22.4. Replay и reorder

- Handshake nonce, cookie lifetime и одноразовый transcript не допускают повторного превращения старого handshake в новую сессию.
- Каждое data-сообщение имеет `(session_id, epoch, packet_number)`.
- AEAD-проверка выполняется до фиксации номера в replay window.
- Номер слишком старый отклоняется до дорогих операций, но «новый» номер нельзя окончательно отмечать до успешной проверки tag.
- При переносе между carrier packet number не сбрасывается.
- Control plane имеет отдельную последовательность и отдельный ключ.
- Resumption ticket одноразовый на сервере; 0-RTT в версии 1 отсутствует.

### 22.5. Unknown-key-share, reflection и downgrade

Защита строится на:

- ролях `client`/`server` в каждой HKDF label;
- разных ключах `c2s` и `s2c`;
- включении обеих identity, key share и suite в transcript;
- фиксированном единственном suite в версии 1;
- запрете молчаливого fallback на другой handshake;
- разных domain separator для handshake, data, control, ticket, migration и manifest.

Получатель никогда не пытается «догадаться», каким ключом расшифровать пакет. Ключ выбирается только по уже проверенному session state и направлению.

### 22.6. Metadata и privacy

Внешний пассивный наблюдатель видит:

- IP/ASN входного узла;
- TCP или UDP, время, размеры, направление и длительность соединения;
- внешние TLS-параметры, которые не скрыты выбранным carrier;
- миграции между адресами, если может коррелировать оба пути.

Оператор входного узла дополнительно видит псевдонимный `client_id` из gate token, но до успешного внутреннего handshake не получает открытый Ed25519 public key и внутренний IP-пакет. Сам VPN-сервер неизбежно видит исходный адрес carrier и расшифрованный туннельный трафик. RekaSerdoba не является анонимизирующей сетью.

Padding снижает точность классификации по размерам, но создаёт накладные расходы и не уничтожает временную корреляцию. Постоянная генерация cover traffic по умолчанию запрещена: она дорога, сама может стать устойчивой сигнатурой и создаёт ложное обещание анонимности.

### 22.7. RNG и nonce safety

Отказ CSPRNG критичен. Требования:

- использовать системный CSPRNG, а не самописный PRNG;
- проверять ошибки ОС;
- не восстанавливать ephemeral keys после crash;
- уникальный packet number на каждый `(key, direction)`;
- атомарно сохранять epoch до активации восстановленной сессии;
- при сомнении в сохранённом состоянии уничтожать сессию и делать полный handshake;
- никогда не применять random nonce вместо счётчика в data plane.

### 22.8. Парсеры

Все длины проверяются до выделения памяти. Запрещены:

- неканонические integer encoding;
- trailing bytes;
- неизвестные critical fields;
- recursion в сообщениях;
- decompression до аутентификации;
- arithmetic overflow при вычислении offsets;
- реакция различного времени на разные причины ошибки admission.

Публичная реализация обязана иметь один canonical encoder и два независимых decoder implementation в тестах.

### 22.9. Чего протокол не гарантирует

RekaSerdoba не гарантирует:

- доступность конкретного IP или домена;
- обход allowlist-only режима;
- неразличимость от любого произвольного веб-сайта;
- защиту заражённого endpoint;
- постквантовую конфиденциальность suite `0x0001`;
- анонимность от сервера;
- устойчивость к глобальному активному противнику, который контролирует оба конца;
- «100% работу» при изменении правил сети.

Фраза «100% будет работать» была бы инженерно ложной. Можно обещать измеримые свойства, быстрый безопасный fallback и отсутствие одного неизменного внешнего признака — не вечную неблокируемость.

---

## 23. Формальная модель и независимый аудит

Собственный AKE — самая рискованная часть проекта. Публиковать production-сборку до независимого криптографического аудита нельзя.

### 23.1. Модель handshake

В Tamarin или ProVerif должны быть представлены:

- Ed25519 как идеальная signature primitive;
- X25519 как DH с обязательным reject all-zero;
- transcript-bound KDF;
- активный Dolev–Yao противник;
- утечка client/server identity key в разные моменты;
- утечка текущего session secret;
- Retry;
- resumption;
- параллельные handshake;
- повтор сообщений;
- смена carrier;
- signed full rekey.

Проверяемые lemmas:

1. mutual injective agreement после `CLIENT_FINISH`;
2. secrecy application keys;
3. forward secrecy при поздней утечке identity key;
4. отсутствие unknown-key-share;
5. отсутствие reflection;
6. binding suite, roles и transcript;
7. невозможность принять старый `SERVER_FINISH` в новой сессии;
8. resumption PSK не заменяет свежий DH;
9. migration не создаёт новую криптографическую сессию;
10. full rekey согласован обеими сторонами или безопасно откатывается.

### 23.2. Модель state machine

Отдельная модель, например в TLA+, проверяет:

- одновременный `KEY_UPDATE_REQUEST`;
- потерянные ACK/COMMIT/DONE;
- crash до и после переключения epoch;
- reorder через два carrier;
- повторную миграцию;
- истечение ticket;
- удаление старых ключей только после grace;
- отсутствие состояния, где стороны навсегда передают в разных epoch.

### 23.3. Аудит

Минимальные независимые работы:

- дизайн-ревью протокола до написания полного клиента;
- аудит cryptographic core;
- аудит Windows service, WFP rules и update mechanism;
- аудит Linux privilege boundaries;
- fuzzing parsers третьей стороной;
- reproducible-build review;
- публичная remediation table.

Аудит «криптобиблиотеки» не равен аудиту протокола. Ошибка обычно возникает в transcript, state transition, nonce lifecycle, recovery или integration.

---

## 24. Стратегия тестирования

### 24.1. Conformance vectors

Репозиторий содержит versioned test vectors:

- deterministic keys только для тестов;
- каждый handshake message до и после encoding;
- transcript после каждого сообщения;
- DH result;
- handshake, master и epoch secrets;
- direction keys/IV;
- nonce для выбранных packet number;
- encrypted records;
- negative vectors с изменённым bit;
- Retry и resumption;
- migration и rekey.

Секретные тестовые значения должны явно маркироваться `TEST ONLY`.

### 24.2. Unit и property tests

- `decode(encode(x)) == x`;
- canonical encoder даёт единственное представление;
- любой truncated input отвергается;
- length arithmetic не переполняется;
- изменение любого authenticated header bit ломает tag;
- один `(key, nonce)` никогда не создаётся дважды;
- replay window корректен на границах 63/64/4095/4096;
- fragment overlap, gap и duplicate отвергаются;
- route policy не позволяет client address spoofing;
- секреты зануляются при drop настолько, насколько позволяет язык и ОС.

### 24.3. Fuzzing

Непрерывно fuzzятся:

- все decoders;
- handshake state machine;
- control state machine;
- H2/H3/WSS adapters;
- fragment reassembly;
- manifest and ticket parser;
- Windows IPC;
- Linux admin API.

Corpus включает реальные capture с удалёнными секретами и синтетические пограничные случаи. Sanitizer jobs выполняются в Linux; Windows получает отдельные AppVerifier/WinDbg jobs.

### 24.4. Differential testing

До open beta создаётся второй минимальный decoder и transcript calculator на Go. Он не становится production-сервером, а служит независимым conformance oracle. Две реализации должны совпадать на vectors и расходиться на intentional invalid cases одинаковым классом ошибки.

### 24.5. Сетевой chaos lab

Тестовая матрица:

- loss: 0, 1, 3, 10, 30%;
- reorder: 0, 1, 10%;
- duplication;
- latency 20–800 ms;
- jitter;
- MTU 576–1500;
- NAT rebinding;
- TCP reset;
- UDP blackhole;
- смена IPv4/IPv6;
- sleep/resume;
- смена Wi-Fi/Ethernet;
- crash в каждой точке update/rekey;
- исчерпание диска и памяти;
- рассинхронизация часов.

Проверяется не только throughput, но и отсутствие plaintext leak, bounded memory, восстановление DNS/routes и понятная диагностика.

### 24.6. DPI/TSPU lab

Правильная цель — не «угадать секретный алгоритм фильтра», а регулярно измерять:

- TCP/UDP connectivity по сетям и регионам;
- успех H3 → H2 → WSS fallback;
- время до классификации/сброса;
- влияние SNI, ASN, размера и cadence;
- active probes;
- false positives decoy;
- длительность жизни ingress;
- различимость положительного и отрицательного admission;
- корреляцию обновления manifest с восстановлением доступности.

Данные агрегируются и лишаются идентификаторов. Никогда нельзя собирать пользовательские destination domains только ради исследования DPI.

### 24.7. Release gates

Релиз блокируется, если:

- есть nonce reuse;
- есть plaintext leak при kill-switch;
- не проходит хотя бы один negative vector;
- decoder panic/crash на fuzz corpus;
- rollback manifest принимается;
- подпись update не проверяется;
- старый revoked client может создать новую сессию;
- не пройдены 24 часа chaos soak;
- изменён wire format без нового protocol version.

---

## 25. Компактный референс cryptographic core на Rust

Это **не готовый production-клиент**, а небольшой ориентир для реализации primitives и record layer. Handshake state machine, TUN, carrier и keystore намеренно остаются отдельными модулями. Версии зависимостей необходимо закрепить lockfile и перепроверить перед сборкой.

```toml
[package]
name = "rekaserdoba-core"
version = "0.1.0"
edition = "2024"

[dependencies]
chacha20poly1305 = "0.11"
hkdf = "0.13"
sha2 = "0.11"
subtle = "2"
zeroize = { version = "1", features = ["derive"] }
```

В реальном репозитории `x25519-dalek`, `ed25519-dalek` и системный RNG добавляются в handshake crate. Код ниже показывает точные правила derivation и AEAD:

```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Debug)]
pub enum CryptoError {
    BadLength,
    Kdf,
    Aead,
}

fn expand_label(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    // length-prefixed поля исключают неоднозначность concatenation.
    if label.len() > 255 || context.len() > u16::MAX as usize {
        return Err(CryptoError::BadLength);
    }
    let mut info = Vec::with_capacity(16 + label.len() + context.len());
    info.extend_from_slice(b"RS1 expand");
    info.push(label.len() as u8);
    info.extend_from_slice(label);
    info.extend_from_slice(&(context.len() as u16).to_be_bytes());
    info.extend_from_slice(context);

    Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| CryptoError::Kdf)?
        .expand(&info, out)
        .map_err(|_| CryptoError::Kdf)
}

pub struct TrafficKey {
    key: [u8; 32],
    iv: [u8; 12],
}

pub fn derive_traffic_key(
    epoch_secret: &[u8; 32],
    direction: &[u8], // только b"c2s data" или b"s2c data"
    epoch: u32,
) -> Result<TrafficKey, CryptoError> {
    let context = epoch.to_be_bytes();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    expand_label(epoch_secret, direction, &context, &mut key)?;

    let mut iv_label = Vec::from(direction);
    iv_label.extend_from_slice(b" iv");
    expand_label(epoch_secret, &iv_label, &context, &mut iv)?;
    Ok(TrafficKey { key, iv })
}

fn packet_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let encoded = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= encoded[i];
    }
    nonce
}

pub fn seal(
    tk: &TrafficKey,
    packet_number: u64,
    authenticated_header: &[u8],
    plaintext_frames: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&tk.key));
    let nonce_bytes = packet_nonce(&tk.iv, packet_number);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext_frames, aad: authenticated_header },
        )
        .map_err(|_| CryptoError::Aead)
}

pub fn open(
    tk: &TrafficKey,
    packet_number: u64,
    authenticated_header: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&tk.key));
    let nonce_bytes = packet_nonce(&tk.iv, packet_number);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: ciphertext_and_tag, aad: authenticated_header },
        )
        .map_err(|_| CryptoError::Aead)
}
```

Replay window фиксирует номер **только после** успешного `open`:

```rust
const W: u64 = 4096;

pub struct ReplayWindow {
    initialized: bool,
    highest: u64,
    bits: [u64; 64],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self { initialized: false, highest: 0, bits: [0; 64] }
    }

    fn slot(n: u64) -> (usize, u64) {
        (((n % W) / 64) as usize, 1u64 << (n % 64))
    }

    pub fn plausible(&self, n: u64) -> bool {
        if !self.initialized { return true; }
        if n.saturating_add(W) <= self.highest { return false; }
        let (word, mask) = Self::slot(n);
        n > self.highest || self.bits[word] & mask == 0
    }

    pub fn commit_authenticated(&mut self, n: u64) -> bool {
        if !self.plausible(n) { return false; }
        if !self.initialized {
            self.initialized = true;
            self.highest = n;
        } else if n > self.highest {
            let delta = n - self.highest;
            if delta >= W {
                self.bits.fill(0);
            } else {
                for cleared in (self.highest + 1)..=n {
                    let (word, mask) = Self::slot(cleared);
                    self.bits[word] &= !mask;
                }
            }
            self.highest = n;
        }
        let (word, mask) = Self::slot(n);
        if self.bits[word] & mask != 0 { return false; }
        self.bits[word] |= mask;
        true
    }
}
```

Production-вариант дополнительно:

- применяет secrecy wrappers и zeroization;
- не хранит ключ в обычном `Clone`;
- использует bounded buffers;
- отделяет precheck от authenticated commit;
- покрывает wraparound и hard packet limit;
- предоставляет constant-time сравнение Finished/token;
- запрещает логирование объектов, содержащих secret;
- получает ключи только из типизированного state machine.

На машине, где готовился этот документ, Rust toolchain отсутствовал, поэтому этот листинг не выдаётся за скомпилированный артефакт. Первое действие в репозитории — создать crate, закрепить актуальные версии, включить `cargo fmt`, `clippy`, `test`, Miri и fuzzing, затем опубликовать conformance vectors.

---

## 26. Предлагаемая структура репозитория

```text
rekaserdoba/
├─ SPEC.md
├─ SECURITY.md
├─ THREAT-MODEL.md
├─ CHANGELOG.md
├─ vectors/
├─ formal/
│  ├─ tamarin/
│  └─ tla/
├─ crates/
│  ├─ rs-codec/          # canonical wire encoding
│  ├─ rs-crypto/         # transcript, KDF, AEAD, signatures
│  ├─ rs-handshake/      # типизированная state machine
│  ├─ rs-record/         # data/control records, replay
│  ├─ rs-carrier/        # общий carrier trait
│  ├─ rs-carrier-h3/
│  ├─ rs-carrier-h2/
│  ├─ rs-carrier-wss/
│  ├─ rs-manifest/
│  ├─ rs-client-core/
│  └─ rs-server-core/
├─ apps/
│  ├─ windows-service/
│  ├─ windows-ui/
│  └─ linux-server/
├─ packaging/
│  ├─ windows/
│  └─ deb/
├─ test-oracle-go/
└─ lab/
   ├─ network-chaos/
   ├─ pcap-analysis/
   └─ dpi-measurement/
```

Почему Rust выбран основным:

- memory safety для сложных сетевых парсеров;
- единое ядро клиента и сервера;
- явные типы для state machine;
- хорошие constant-time/zeroization библиотеки;
- удобная сборка статических server binaries.

Go используется только как независимый oracle и для части лабораторной автоматизации. Две production-реализации на старте удвоили бы поверхность ошибок.

---

## 27. План реализации

### Этап 0 — specification freeze

- закрепить terminology и binary layouts;
- назначить номера всех messages/frames/errors;
- создать vectors;
- завершить Tamarin/TLA+ model;
- провести внешний design review.

Критерий выхода: два независимых инженера могут получить одинаковый transcript и ключи без чтения исходника друг друга.

### Этап 1 — cryptographic core

- canonical codec;
- transcript;
- handshake state machine;
- record layer;
- replay;
- key update/full rekey;
- resumption;
- manifest verification;
- fuzz/property tests.

Критерий выхода: весь core работает без сокетов и проходит vectors.

### Этап 2 — loopback tunnel

- Linux server TUN;
- Windows service + Wintun;
- статическая конфигурация;
- H2 carrier первым;
- IPv4 full tunnel;
- DNS;
- kill switch;
- crash-safe cleanup.

Критерий выхода: 24-часовой soak без plaintext leak.

### Этап 3 — carrier agility

- H3/WebTransport carrier;
- WSS fallback;
- carrier scoring;
- migration;
- signed manifest;
- decoy frontend;
- IPv6 и split tunnel policy.

Критерий выхода: активная сессия переживает UDP blackhole и смену сети.

### Этап 4 — hardening

- privilege separation;
- updater;
- reproducible builds;
- key rotation ceremony;
- external audits;
- signed release metadata;
- privacy-preserving telemetry;
- incident playbooks.

### Этап 5 — open source beta

- публичный spec и vectors;
- минимальный deployment guide;
- disclosure policy;
- compatibility policy;
- security contact;
- запрет marketing claims о гарантированной неблокируемости.

---

## 28. Практические и исследовательские идеи

### 28.1. Реализуемо в первой стабильной версии

1. **Криптографическая сессия вне carrier.** Смена H3/H2/WSS не меняет identity и session semantics.
2. **Подписанный manifest.** Быстрое обновление ingress и policy без обновления бинарника.
3. **Псевдонимный admission.** Незнакомый запрос выглядит как обычный frontend и не запускает дорогой handshake.
4. **Full signed rekey.** Возможность восстановиться после потенциальной утечки session secret.
5. **Два независимых conformance engine.** Rust production и Go test oracle уменьшают риск двусмысленной спецификации.
6. **Transactional Windows networking.** Kill switch, DNS и routes рассматриваются как часть безопасности протокола, а не UI-функция.

### 28.2. Версия 1.x после измерений

**Profile compiler.** Вместо одного вечного набора padding/timing параметров подписанный manifest выбирает ограниченный, версионированный профиль для конкретного carrier. Профиль не меняет криптографию и не может ослабить минимальные limits. Новизна здесь не в случайном «шуме», а в строгом разделении стабильного inner protocol и обновляемого внешнего поведения.

**Ephemeral ingress leases.** Manifest может выдавать короткоживущий набор ingress с overlap и threshold approval. Это уменьшает ценность долговременного списка адресов. Необходимо учитывать стоимость, DNS/cache lag и риск превращения ротации в собственную сигнатуру.

**Carrier race with budget.** При плохой истории сети клиент может параллельно начать максимум два carrier attempt и оставить первый подтверждённый. Это сокращает время восстановления, но требует жёсткого rate/bandwidth budget.

**Privacy-preserving health reports.** Клиент сообщает только coarse bucket: carrier, success stage, latency band и manifest version, без destination, полного IP и постоянного device ID.

### 28.3. Исследовательское, не обещание

**Hybrid post-quantum handshake.** Будущий suite может смешать X25519 и стандартизованный KEM через комбинированный extract. Его нельзя «добавить полем»: нужны новые размеры, transcript rules, downgrade protection, DoS budget и аудит. Версия 1 не заявляет PQ-защиту.

**Threshold-signed manifests.** Критичные изменения ingress/root keys принимаются при подписях нескольких offline/online ролей. Это полезно против компрометации control plane, но усложняет emergency rotation.

**Pluggable relay rendezvous.** Разделение первого rendezvous и data ingress может уменьшить долговечность наблюдаемой инфраструктуры. Оно не помогает при полном allowlist и увеличивает доверенную поверхность.

**Adaptive padding under a privacy budget.** Алгоритм может выбирать несколько заранее проверенных distributions на основе локальных измерений, не отправляя raw trace на сервер. Самообучающийся генератор в production без ограничений запрещён: его поведение трудно анализировать и воспроизводить.

Прорывом следует считать не «магический пакет, который DPI не узнает», а систему, где криптография, carrier, конфигурация и сетевое восстановление независимо обновляются и измеряются.

---

## 29. Сравнение подходов

| Подход | Что RekaSerdoba берёт как урок | Что не копируется |
|---|---|---|
| TLS 1.3 | transcript, HKDF separation, Finished discipline | TLS record/handshake как внутренний VPN-протокол |
| WireGuard | небольшой набор primitives, direction keys, rekey discipline | Noise handshake, wire format, kernel/module core |
| QUIC | connection migration, multiplexed streams и optional datagrams как carrier features | QUIC crypto как inner security |
| OpenVPN | зрелость deployment и transport fallback | собственный узнаваемый framing поверх TCP |
| Shadowsocks-подобные системы | важность минимальной реакции на probes | модель «один shared password на всех» |
| MASQUE-подобные tunneling approaches | web-compatible carriers | зависимость внутренней identity от одного HTTP semantics |

Итог: RekaSerdoba действительно имеет собственные handshake messages, key schedule, data/control record, replay, rekey, resumption и migration binding. Стандартными остаются математические primitives — создание собственной кривой, хеша или AEAD было бы неоправданным риском.

---

## 30. Эксплуатационные правила

### 30.1. Key rotation

- TLS certificate — обычная автоматизированная WebPKI-ротация.
- Server Ed25519 identity — overlap старого/нового ключа через подписанный manifest.
- Manifest root — offline ceremony и emergency recovery.
- Ticket keys — короткая ротация с bounded decrypt overlap.
- `K_gate` — отдельно на устройство, отзыв без смены ключей других клиентов.

### 30.2. Обновления

Windows updater:

- проверяет подпись release metadata и payload;
- использует anti-rollback counter;
- устанавливает atomically;
- хранит одну known-good версию;
- не отключает kill switch в середине update;
- не получает команды выполнения произвольной строки.

Server deployment:

- canary;
- совместимость минимум с одной предыдущей minor version;
- drain sessions;
- rollback binaries, но не security counters/keys;
- schema migration отдельно от service restart.

### 30.3. Incident response

При утечке:

1. определить класс ключа;
2. отозвать затронутые credentials;
3. выпустить подписанный manifest;
4. принудить новый полный handshake;
5. сменить tickets и admission keys;
6. сохранить минимально необходимые forensic artifacts;
7. опубликовать scope и remediation;
8. проверить, не было ли rollback/update compromise.

---

## 31. Реестр wire values версии 1

Все незарегистрированные значения в `0x00–0x7f` считаются critical и вызывают `UNSUPPORTED_CRITICAL`; `0x80–0xff` резервируются для ignorable extension только там, где поле явно допускает extensions.

### Handshake message

| Value | Name |
|---:|---|
| `0x01` | CLIENT_HELLO |
| `0x02` | SERVER_RETRY |
| `0x03` | SERVER_HELLO |
| `0x04` | CLIENT_AUTH |
| `0x05` | SERVER_FINISH |
| `0x06` | CLIENT_FINISH |

### Data frame

| Value | Name |
|---:|---|
| `0x00` | PADDING |
| `0x01` | IPV4_PACKET |
| `0x02` | IPV6_PACKET |
| `0x03` | FRAGMENT |
| `0x04` | KEEPALIVE |
| `0x05` | PATH_SIGNAL |

### Control frame

| Value | Name |
|---:|---|
| `0x01` | KEY_UPDATE |
| `0x02` | KEY_UPDATE_ACK |
| `0x03` | KEY_UPDATE_COMMIT |
| `0x04` | KEY_UPDATE_DONE |
| `0x05` | FULL_REKEY_INIT |
| `0x06` | FULL_REKEY_REPLY |
| `0x07` | FULL_REKEY_CONFIRM |
| `0x08` | MIGRATE |
| `0x09` | PATH_CHALLENGE |
| `0x0a` | PATH_RESPONSE |
| `0x0b` | CLOSE |
| `0x0c` | SERVER_KEY_UPDATE_REQUEST |

Числа становятся нормативными только после freeze и публикации vectors. До этого документ имеет статус draft.

---

## 32. Чек-лист перед первым публичным сервером

- [ ] Protocol version и suite заморожены.
- [ ] Test vectors опубликованы.
- [ ] Tamarin/ProVerif lemmas пройдены.
- [ ] TLA+ state model проверена.
- [ ] Нет custom crypto primitive.
- [ ] All-zero X25519 output отклоняется.
- [ ] Finished сравнивается constant-time.
- [ ] Packet number не повторяется после crash.
- [ ] Replay commit только после AEAD success.
- [ ] Старые epoch keys удаляются.
- [ ] 0-RTT отсутствует.
- [ ] Manifest имеет expiry и anti-rollback.
- [ ] Update подписан отдельным ключом.
- [ ] WFP kill switch проверен на boot/update/crash.
- [ ] DNS leak tests пройдены.
- [ ] IPv6 либо полностью работает, либо блокируется.
- [ ] TUN source spoofing блокируется.
- [ ] Decoy не раскрывает admission различием ответов.
- [ ] Logs не содержат payload/destination/secrets.
- [ ] Fuzzing работает постоянно.
- [ ] Внешний audit закрыт с публичной remediation.

---

## 33. Источники и основания решений

Криптографические primitives и модели:

- [RFC 7748 — Elliptic Curves for Security (X25519)](https://datatracker.ietf.org/doc/rfc7748/)
- [RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032/)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/info/rfc5869/)
- [RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc8439)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/info/rfc8446/)
- [RFC 6479 — IPsec Anti-Replay Algorithm without Bit Shifting](https://www.rfc-editor.org/info/rfc6479/)

Кодирование и конфигурация:

- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9052 — COSE Structures and Process](https://www.rfc-editor.org/rfc/rfc9052.html)

Платформы:

- [Wintun — Layer 3 TUN Driver for Windows](https://www.wintun.net/)
- [Linux Universal TUN/TAP documentation](https://docs.kernel.org/networking/tuntap.html)

Исследования блокировок и fingerprinting:

- [How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic](https://gfw.report/publications/usenixsecurity23/en/)
- [OpenVPN is Open to VPN Fingerprinting](https://arxiv.org/abs/2403.03998)
- [Техническое исследование российского ТСПУ, IMC 2022](https://ensa.fi/papers/tspu-imc22.pdf)

Документация Rust-библиотек:

- [RustCrypto HKDF](https://docs.rs/hkdf/latest/hkdf/)
- [RustCrypto ChaCha20Poly1305](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/)
- [x25519-dalek](https://docs.rs/x25519-dalek/latest/x25519_dalek/)
- [ed25519-dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/)

Источники используются как основание для primitives, моделей атак и платформенных API. Они не превращают RekaSerdoba в производное ядро другого VPN.

---

## 34. Итоговая инженерная позиция

RekaSerdoba — новый VPN-протокол прикладного уровня с собственными:

- mutual-auth handshake;
- transcript и key schedule;
- data/control plane;
- packet numbering и replay protection;
- key update и full rekey;
- resumption без 0-RTT;
- binding к carrier и migration;
- signed configuration model;
- Windows/Linux lifecycle.

Он сознательно не изобретает криптографические primitives. Это не компромисс с требованием «с нуля», а необходимая граница: протокол проектируется заново, криптография берётся стандартизованная и анализируемая.

Наиболее реалистичная стратегия для российских сетевых условий — не один маскировочный трюк, а независимость внутренней криптографической сессии от внешнего carrier, обновляемый подписанный manifest, несколько транспортных путей, корректная миграция и непрерывные измерения. Даже эта архитектура не даёт вечной гарантии доступности: блокировка IP, allowlist или изменение активного классификатора может потребовать новой инфраструктуры и нового carrier profile.

До формальной проверки, interoperability vectors, fuzzing, аудита и полноценного прототипа статус проекта остаётся **research draft**.
