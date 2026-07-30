# RekaSerdoba Windows client

Это рабочий research-клиент для Windows 10/11 x64. Он проверяет подписанный COSE manifest, хранит anti-rollback sequence, выполняет RS-HS/1 и RS-DP/1, выбирает H3 → H2 → WSS с cooldown/backoff, хранит device bundle через machine-scope DPAPI и использует официальный подписанный Wintun.

Служба:

- работает как `LocalSystem`;
- создаёт Wintun adapter `RekaSerdoba`;
- добавляет endpoint exception до default routes;
- включает endpoint route и два IPv4 tunnel routes только после успешного рукопожатия;
- передаёт H3 data records через WebTransport datagrams, H3 control records через надёжный stream, а резервные соединения через H2/WSS framing;
- автоматически снимает tunnel routes при остановке или аварии транспорта;
- не меняет глобальную outbound-политику Windows Firewall.

Простая установка:

1. Запустить `RekaSerdoba_Setup.exe` двойным щелчком.
2. Подтвердить запрос Windows на права администратора.
3. Нажать `Да` в окне установки.
4. Дождаться сообщения `RekaSerdoba установлена и запущена`.

Установщик уже содержит клиент, Wintun и персональный профиль подключения. После установки удалить клиент можно через `Параметры` → `Приложения` → `Установленные приложения` → `RekaSerdoba`.

Ручная установка из PowerShell от администратора:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1 -Bundle C:\secure\RekaSerdoba_client_bundle.json
```

Диагностика:

```powershell
& "$env:ProgramFiles\RekaSerdoba\reka-service.exe" check
Get-Service RekaSerdoba
Get-Content "$env:ProgramData\RekaSerdoba\service.log" -Tail 100
```

Аварийное восстановление маршрутов:

```powershell
& "$env:ProgramFiles\RekaSerdoba\reka-service.exe" recover
```

Удаление службы:

```powershell
.\uninstall.ps1
```

Формальные external audit, differential decoder и 24-часовой chaos/fuzz release gate ещё не пройдены. Клиент нельзя использовать для критичных данных до их закрытия.
