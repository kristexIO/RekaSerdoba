import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import winreg
from pathlib import Path


SERVICE_NAME = "RekaSerdoba"
DISPLAY_NAME = "RekaSerdoba"
PRODUCT_VERSION = "0.1.0"
ASSETS = (
    "RekaSerdoba.exe",
    "reka-service.exe",
    "h3_bridge.exe",
    "wintun.dll",
    "RekaSerdoba_client_bundle.json",
    "WINTUN_LICENSE.txt",
)
CREATE_NO_WINDOW = 0x08000000
MB_OK = 0x00000000
MB_ICONINFORMATION = 0x00000040
MB_ICONERROR = 0x00000010
MB_YESNO = 0x00000004
MB_ICONQUESTION = 0x00000020
IDYES = 6


def message(text, title=DISPLAY_NAME, flags=MB_OK | MB_ICONINFORMATION):
    return ctypes.windll.user32.MessageBoxW(None, text, title, flags)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def quote_argument(value):
    return subprocess.list2cmdline([str(value)])


def elevate(arguments):
    parameters = " ".join(quote_argument(value) for value in arguments)
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        parameters,
        None,
        1,
    )
    if result <= 32:
        raise RuntimeError("Запрос прав администратора был отменён")


def resource_dir():
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def target_dir():
    return Path(os.environ["ProgramFiles"]) / "RekaSerdoba"


def run(command, check=True):
    return subprocess.run(
        [str(value) for value in command],
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=CREATE_NO_WINDOW,
    )


def service_exists():
    return run(["sc.exe", "query", SERVICE_NAME], check=False).returncode == 0


def wait_for_service_absence(timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not service_exists():
            return
        time.sleep(0.5)
    raise RuntimeError("Не удалось удалить прежнюю службу")


def stop_existing_service(directory):
    if not service_exists():
        return
    run(["sc.exe", "stop", SERVICE_NAME], check=False)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        query = run(["sc.exe", "query", SERVICE_NAME], check=False)
        if "STOPPED" in query.stdout:
            break
        time.sleep(0.5)
    service = directory / "reka-service.exe"
    if service.exists():
        run([service, "recover"], check=False)
    run(["sc.exe", "delete", SERVICE_NAME], check=True)
    wait_for_service_absence()


def validate_assets():
    source = resource_dir()
    missing = [name for name in ASSETS if not (source / name).is_file()]
    if missing:
        raise RuntimeError("В установщике отсутствуют: " + ", ".join(missing))
    bundle = json.loads(
        (source / "RekaSerdoba_client_bundle.json").read_text(encoding="utf-8")
    )
    required = {
        "endpoint",
        "client_id_b64",
        "client_signing_seed_b64",
        "server_public_key_b64",
        "manifest_signing_public_key_b64",
    }
    absent = sorted(required.difference(bundle))
    if absent:
        raise RuntimeError("Конфигурация неполная: " + ", ".join(absent))


def copy_assets(destination):
    source = resource_dir()
    destination.mkdir(parents=True, exist_ok=True)
    for name in ASSETS:
        shutil.copy2(source / name, destination / name)
    shutil.copy2(Path(sys.executable), destination / "RekaSerdoba_Setup.exe")


def register_uninstaller(destination):
    key_path = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RekaSerdoba"
    )
    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE,
        key_path,
        0,
        winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY,
    ) as key:
        setup = destination / "RekaSerdoba_Setup.exe"
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, DISPLAY_NAME)
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, PRODUCT_VERSION)
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "RekaSerdoba")
        winreg.SetValueEx(
            key,
            "UninstallString",
            0,
            winreg.REG_SZ,
            f'"{setup}" --uninstall',
        )
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)


def shortcut_paths():
    return (
        Path(os.environ["PUBLIC"]) / "Desktop" / "RekaSerdoba.lnk",
        Path(os.environ["ProgramData"])
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "RekaSerdoba.lnk",
    )


def create_shortcuts(destination):
    target = destination / "RekaSerdoba.exe"
    for shortcut in shortcut_paths():
        shortcut.parent.mkdir(parents=True, exist_ok=True)
        script = (
            "$w=New-Object -ComObject WScript.Shell;"
            f"$s=$w.CreateShortcut('{shortcut}');"
            f"$s.TargetPath='{target}';"
            f"$s.WorkingDirectory='{destination}';"
            "$s.Description='RekaSerdoba secure tunnel';"
            "$s.Save()"
        )
        run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])


def remove_shortcuts():
    for shortcut in shortcut_paths():
        shortcut.unlink(missing_ok=True)


def unregister_uninstaller():
    key_path = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RekaSerdoba"
    )
    try:
        winreg.DeleteKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            winreg.KEY_WOW64_64KEY,
            0,
        )
    except FileNotFoundError:
        pass


def schedule_cleanup(destination):
    for path in destination.iterdir():
        ctypes.windll.kernel32.MoveFileExW(str(path), None, 4)
    ctypes.windll.kernel32.MoveFileExW(str(destination), None, 4)


def install():
    validate_assets()
    destination = target_dir()
    run(["taskkill.exe", "/IM", "RekaSerdoba.exe", "/F"], check=False)
    stop_existing_service(destination)
    copy_assets(destination)
    service = destination / "reka-service.exe"
    bundle = destination / "RekaSerdoba_client_bundle.json"
    run([service, "import", bundle])
    check = run([service, "check"])
    run([service, "install"])
    run([service, "start"])
    time.sleep(3)
    query = run(["sc.exe", "query", SERVICE_NAME])
    if "RUNNING" not in query.stdout:
        raise RuntimeError("Служба установлена, но не перешла в состояние RUNNING")
    register_uninstaller(destination)
    create_shortcuts(destination)
    return check.stdout.strip()


def recover_after_failure():
    service = target_dir() / "reka-service.exe"
    if service.exists():
        run([service, "recover"], check=False)


def uninstall():
    destination = target_dir()
    stop_existing_service(destination)
    unregister_uninstaller()
    remove_shortcuts()
    if destination.exists():
        schedule_cleanup(destination)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--elevated", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        validate_assets()
        return
    if not is_admin():
        elevated_args = ["--elevated"]
        if args.uninstall:
            elevated_args.append("--uninstall")
        try:
            elevate(elevated_args)
        except Exception as error:
            message(str(error), flags=MB_OK | MB_ICONERROR)
        return
    if args.uninstall:
        if message(
            "Удалить службу RekaSerdoba и восстановить сетевые настройки?",
            flags=MB_YESNO | MB_ICONQUESTION,
        ) != IDYES:
            return
        try:
            uninstall()
            message("RekaSerdoba удалена. Сетевые настройки восстановлены.")
        except Exception as error:
            message(str(error), flags=MB_OK | MB_ICONERROR)
        return
    if message(
        "Установить и запустить защищённое подключение RekaSerdoba?",
        flags=MB_YESNO | MB_ICONQUESTION,
    ) != IDYES:
        return
    try:
        result = install()
        message(
            "RekaSerdoba установлена и запущена.\n\n"
            f"Проверка соединения: {result or 'успешно'}"
        )
        subprocess.Popen([str(target_dir() / "RekaSerdoba.exe")])
    except Exception as error:
        recover_after_failure()
        message(
            "Установка не завершена. Сетевые настройки восстановлены.\n\n"
            + str(error),
            flags=MB_OK | MB_ICONERROR,
        )


if __name__ == "__main__":
    main()
