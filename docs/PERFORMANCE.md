# Производительность и стабильность

## Цели release gate

| Показатель | Цель |
|---|---|
| readiness после обычного restart | не более 10 секунд |
| readiness после helper restart | не более 5 секунд без restart edge |
| packet drops при штатной пропускной способности | 0 |
| carrier buffer | не более 1 MiB на H2/H3 stream |
| H3 decoy response | не более 1 MiB |
| активные carrier tasks | не более 1024 |
| H3 handshake/decoy connections | не более 256 |
| graceful drain | не более 15 секунд |

Это пороги приёмки, а не опубликованные результаты benchmark.

## Что оптимизировано

- H2/H3 framing использует `BytesMut::split_to` без линейного `Vec::drain`;
- очереди TUN и carrier bounded;
- bandwidth policy задерживает трафик вместо разрыва сессии;
- burst ограничен диапазоном 16 KiB–4 MiB;
- H3 connections и decoy requests ограничены semaphore;
- UDP receive/send buffers и backlog заданы sysctl profile;
- helper restart восстанавливается через periodic registration/ACK.

## Измерение

Снимать одновременно:

```bash
curl --silent http://127.0.0.1:9080/healthz
pidstat -p "$(systemctl show -p MainPID --value rekaserdoba.service)" 1
ss -u -a -m
ip -s link show reka0
journalctl -u rekaserdoba.service --since "-10 min" --no-pager
```

Нагрузка должна использовать отдельные тестовые identities и адреса, потому что сервер допускает одну активную сессию на tunnel IPv4. Проверять WSS, H2 и H3 раздельно, затем migration. Результат фиксировать вместе с commit SHA, VM size, kernel, carrier, RTT, packet size и числом сессий.

## Fault scenarios

- restart helper при активном edge;
- временное удаление helper socket на staging;
- блокировка UDP/443 с переходом H3 → H2;
- обрыв TCP carrier и повторное подключение;
- fragmented/coalesced carrier frames;
- malformed record corpus;
- исчерпание session queue;
- SIGTERM с активными сессиями;
- невалидный TLS key, duplicate tunnel IP и просроченный certificate.

Fault injection с firewall, socket deletion и clock shift выполняется только на staging.
