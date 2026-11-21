#!/usr/bin/env python3
import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REQUIRED_BINARIES = {
    "wpa_supplicant": "wpa_supplicant",
    "pixiewps": "pixiewps",
    "iw": "iw",
    "ip": "iproute2",
}


def run_cmd(cmd: list[str], check: bool = True) -> int:
    print(f"[*] Виконую: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, check=check)
        return res.returncode
    except FileNotFoundError:
        print(f"[-] Команду не знайдено: {cmd[0]}")
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"[-] Помилка виконання (код {exc.returncode}): {' '.join(cmd)}")
        if check:
            raise
        return exc.returncode


def detect_linux_pkg_manager() -> str | None:
    managers = [
        ("apt-get", "apt"),
        ("pacman", "pacman"),
        ("dnf", "dnf"),
        ("zypper", "zypper"),
        ("apk", "apk"),
    ]
    for binary, name in managers:
        if shutil.which(binary):
            return name
    return None


def install_linux_system_deps(pkg_mgr: str, dry_run: bool = False) -> None:
    if os.geteuid() != 0:
        if shutil.which("sudo"):
            prefix = ["sudo"]
        else:
            print("[-] Потрібні права root або утиліта sudo для встановлення системних пакетів.")
            sys.exit(1)
    else:
        prefix = []

    pkg_maps = {
        "apt": ["wpa_supplicant", "pixiewps", "iw", "iproute2", "python3-pip"],
        "pacman": ["wpa_supplicant", "pixiewps", "iw", "iproute2", "python-pip"],
        "dnf": ["wpa_supplicant", "pixiewps", "iw", "iproute-tc", "python3-pip"],
        "zypper": ["wpa_supplicant", "pixiewps", "iw", "iproute2", "python3-pip"],
        "apk": ["wpa_supplicant", "pixiewps", "iw", "iproute2", "py3-pip"],
    }

    packages = pkg_maps.get(pkg_mgr, list(REQUIRED_BINARIES.values()))

    if pkg_mgr == "apt":
        cmds = [
            prefix + ["apt-get", "update"],
            prefix + ["apt-get", "install", "-y"] + packages,
        ]
    elif pkg_mgr == "pacman":
        cmds = [
            prefix + ["pacman", "-Sy", "--noconfirm"] + packages,
        ]
    elif pkg_mgr == "dnf":
        cmds = [
            prefix + ["dnf", "install", "-y"] + packages,
        ]
    elif pkg_mgr == "zypper":
        cmds = [
            prefix + ["zypper", "--non-interactive", "install"] + packages,
        ]
    elif pkg_mgr == "apk":
        cmds = [
            prefix + ["apk", "update"],
            prefix + ["apk", "add"] + packages,
        ]
    else:
        print(f"[-] Непідтримуваний пакетний менеджер: {pkg_mgr}")
        return

    for cmd in cmds:
        if dry_run:
            print(f"[DRY-RUN] {' '.join(cmd)}")
        else:
            run_cmd(cmd, check=False)


def install_python_deps(target_dir: Path, dry_run: bool = False) -> None:
    req_file = target_dir / "requirements.txt"
    if req_file.exists():
        cmd = [sys.executable, "-m", "pip", "install", "-r", str(req_file)]
        if dry_run:
            print(f"[DRY-RUN] {' '.join(cmd)}")
        else:
            run_cmd(cmd, check=False)
    else:
        print("[*] Файл requirements.txt не знайдено — додаткові pip-пакети не потрібні.")


def verify_environment() -> None:
    print("\n=== Перевірка залежностей ===")
    system_name = platform.system()
    print(f"ОС: {system_name} ({platform.release()})")

    if system_name == "Windows":
        print(
            "[!] УВАГА: Основний скрипт використовує модулі (pty) та утиліти Linux "
            "(ip, iw, wpa_supplicant, nmcli). На Windows без WSL2/Linux запуск не підтримується."
        )

    for binary, pkg in REQUIRED_BINARIES.items():
        path = shutil.which(binary)
        status = f"OK ({path})" if path else f"ВІДСУТНІЙ (пакет: {pkg})"
        print(f"  - {binary}: {status}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Встановлення системних і Python-залежностей для основного скрипта."
    )
    parser.add_argument(
        "--dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Директорія проєкту для пошуку requirements.txt (за замовчуванням — папка скрипта)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Лише показати команди без їх виконання",
    )
    args = parser.parse_args()

    target_dir = args.dir.resolve()
    system_name = platform.system()

    if system_name == "Linux":
        pkg_mgr = detect_linux_pkg_manager()
        if pkg_mgr:
            print(f"[*] Виявлено пакетний менеджер Linux: {pkg_mgr}")
            install_linux_system_deps(pkg_mgr, dry_run=args.dry_run)
        else:
            print("[-] Не вдалося визначити відомий пакетний менеджер Linux.")
    elif system_name == "Windows":
        print("[!] Виявлено Windows. Системні пакети Linux (wpa_supplicant, pixiewps, iw, iproute2) недоступні нативно.")
    else:
        print(f"[!] Платформа {system_name} частково підтримується.")

    install_python_deps(target_dir, dry_run=args.dry_run)
    verify_environment()


if __name__ == "__main__":
    main()
