#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AetherPulse - Secure Wi-Fi WPS Audit Tool
Refactored, modular, and secure architecture with robust resource management.
"""

import sys
import os
import re
import csv
import json
import time
import socket
import shutil
import logging
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Налаштування централізованого логування
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("AetherPulse")


class NetworkAddress:
    """Клас для валідації та представлення MAC-адрес з регулярними виразами."""
    MAC_REGEX = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')

    def __init__(self, mac: str):
        if isinstance(mac, str):
            clean_mac = mac.strip()
            if not self.MAC_REGEX.match(clean_mac):
                raise ValueError(f"Invalid MAC address format: {mac}")
            self._str_repr = clean_mac.replace('-', ':').upper()
            self._int_repr = int(self._str_repr.replace(':', ''), 16)
        elif isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self) -> str:
        return self._str_repr

    @property
    def integer(self) -> int:
        return self._int_repr

    @staticmethod
    def _int2mac(mac: int) -> str:
        mac_hex = hex(mac).split('x')[-1].upper().zfill(12)
        return ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))

    def __str__(self) -> str:
        return self.string

    def __int__(self) -> int:
        return self.integer


class WPSpin:
    """Генератор WPS PIN-кодів за алгоритмами та вендорськими масками."""
    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2

        self.algos = {
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': lambda m: m.integer & 0xFFFFFF},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': lambda m: m.integer & 0xFFFFFFF},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': lambda m: m.integer % 0x100000000},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self._gen_asus},
            'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda m: ''},
            'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda m: 1234567},
            'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda m: 2017252},
        }

    @staticmethod
    def _gen_asus(mac: NetworkAddress) -> int:
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % 10)
        return int(pin)

    @staticmethod
    def checksum(pin: int) -> int:
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo: str, mac: NetworkAddress) -> str:
        if algo not in self.algos:
            raise ValueError('Invalid WPS pin algorithm')
        pin = self.algos[algo]['gen'](mac)
        if algo == 'pinEmpty':
            return str(pin)
        pin = pin % 10000000
        pin_str = str(pin) + str(self.checksum(pin))
        return pin_str.zfill(8)

    def getSuggested(self, mac_str: str) -> List[dict]:
        mac = NetworkAddress(mac_str)
        res = []
        for ID, algo in self.algos.items():
            if algo['mode'] != self.ALGO_EMPTY:
                try:
                    res.append({
                        'id': ID,
                        'name': algo['name'],
                        'pin': self.generate(ID, mac)
                    })
                except Exception:
                    continue
        return res


class InterfaceManager:
    """Менеджер для безпечного керування станом бездротового інтерфейсу без shell=True."""
    @staticmethod
    def set_interface_state(iface: str, down: bool = False) -> bool:
        action = 'down' if down else 'up'
        try:
            res = subprocess.run(
                ['ip', 'link', 'set', iface, action],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to set interface {iface} {action}: {e}")
            return False


class WiFiScanner:
    """Сканування мереж через виклик iw без shell=True."""
    def __init__(self, interface: str):
        self.interface = interface

    def iw_scanner(self) -> Dict[int, dict]:
        try:
            proc = subprocess.run(
                ['iw', 'dev', self.interface, 'scan'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            if proc.returncode != 0:
                logger.error(f"Scan failed: {proc.stderr.strip()}")
                return {}

            lines = proc.stdout.splitlines()
            networks = []
            current = None

            for line in lines:
                if line.strip().startswith('BSS '):
                    if current:
                        networks.append(current)
                    parts = line.strip().split()
                    current = {'BSSID': parts[1], 'WPS': False, 'ESSID': 'HIDDEN', 'Level': -100}
                elif current:
                    if 'SSID:' in line:
                        current['ESSID'] = line.split('SSID:')[1].strip()
                    elif 'signal:' in line:
                        try:
                            current['Level'] = float(line.split('signal:')[1].split()[0])
                        except Exception:
                            pass
                    elif 'WPS:' in line:
                        current['WPS'] = True

            if current:
                networks.append(current)

            networks = [n for n in networks if n['WPS']]
            networks.sort(key=lambda x: x['Level'], reverse=True)
            return {(i + 1): net for i, net in enumerate(networks)}
        except Exception as e:
            logger.error(f"Error during network scanning: {e}")
            return {}

    def prompt_network(self) -> List[str]:
        networks = self.iw_scanner()
        if not networks:
            logger.warning('No WPS-enabled networks found.')
            sys.exit(1)

        print('\nAvailable WPS Networks:')
        for n, net in networks.items():
            print(f"{n}) BSSID: {net['BSSID']} | ESSID: {net['ESSID']} | PWR: {net['Level']}dBm")

        while True:
            choice = input('\nSelect targets (e.g. 1-3, 1 2 4, or 0 for all): ').strip()
            selected_bssids = []
            try:
                if choice == '0':
                    return [net['BSSID'] for net in networks.values()]
                if '-' in choice:
                    start, end = map(int, choice.split('-'))
                    for i in range(start, end + 1):
                        if i in networks:
                            selected_bssids.append(networks[i]['BSSID'])
                else:
                    for p in map(int, choice.split()):
                        if p in networks:
                            selected_bssids.append(networks[p]['BSSID'])
                if selected_bssids:
                    return selected_bssids
            except ValueError:
                pass
            print('[-] Invalid selection. Try again.')


class Companion:
    """Клас керування аудитом WPS з захищеним контекстним менеджером."""
    def __init__(self, interface: str, save_result: bool = False, bssid: str = ''):
        self.interface = interface
        self.save_result = save_result
        self.bssid = bssid
        self.tempdir = tempfile.mkdtemp()
        self.tempconf = os.path.join(self.tempdir, 'wpa_supplicant.conf')
        self.wpas_ctrl_path = f"{self.tempdir}/{interface}"
        
        # Безпечніший файл для зворотного сокета
        self.res_socket_file = os.path.join(self.tempdir, f"retsock_{os.getpid()}")
        
        self.wpas = None
        self.retsock = None
        self.reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'reports')

    def __enter__(self):
        try:
            with open(self.tempconf, 'w') as f:
                f.write(f'ctrl_interface={self.tempdir}\nctrl_interface_group=root\nupdate_config=1\n')

            self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.retsock.bind(self.res_socket_file)
            self.retsock.settimeout(5.0)

            cmd = [
                'wpa_supplicant', '-K', '-d',
                '-Dnl80211,wext,hostapd,wired',
                f'-i{self.interface}',
                f'-c{self.tempconf}'
            ]
            self.wpas = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            start_time = time.time()
            while not os.path.exists(self.wpas_ctrl_path):
                if time.time() - start_time > 5.0:
                    raise TimeoutError("Timeout waiting for wpa_supplicant control socket.")
                time.sleep(0.1)

            return self
        except Exception as e:
            logger.error(f"Initialization failed inside context manager: {e}")
            self.cleanup()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        try:
            if self.retsock:
                self.retsock.close()
        except Exception:
            pass
        try:
            if self.wpas:
                self.wpas.terminate()
                self.wpas.wait(timeout=2)
        except Exception:
            if self.wpas:
                self.wpas.kill()
        try:
            shutil.rmtree(self.tempdir, ignore_errors=True)
        except Exception:
            pass

    def send_and_receive(self, command: str) -> str:
        try:
            if not self.retsock:
                return ""
            self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
            b, _ = self.retsock.recvfrom(4096)
            return b.decode('utf-8', errors='replace')
        except socket.timeout:
            logger.error("Socket operation timed out.")
            return ""
        except Exception as e:
            logger.error(f"Error in send_and_receive: {e}")
            return ""

    def save_result_reports(self, bssid: str, wps_pin: str, wpa_psk: str):
        os.makedirs(self.reports_dir, exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        csv_path = os.path.join(self.reports_dir, 'stored.csv')
        file_exists = os.path.exists(csv_path)
        with open(csv_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';', quoting=csv.QUOTE_ALL)
            if not file_exists:
                writer.writerow(['Timestamp', 'BSSID', 'WPS PIN', 'WPA PSK'])
            writer.writerow([date_str, bssid, wps_pin, wpa_psk])

        json_path = os.path.join(self.reports_dir, 'stored.json')
        data = []
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r', encoding='utf-8') as jf:
                    data = json.load(jf)
            except Exception:
                data = []

        data.append({
            "timestamp": date_str,
            "bssid": bssid,
            "wps_pin": wps_pin,
            "wpa_psk": wpa_psk
        })

        with open(json_path, 'w', encoding='utf-8') as jf:
            json.dump(data, jf, indent=4, ensure_ascii=False)
        
        logger.info(f"Results saved to reports/ for target {bssid}")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='AetherPulse - Secure Wi-Fi WPS Audit Tool')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Wireless interface')
    parser.add_argument('-b', '--bssid', type=str, help='Target BSSID')
    parser.add_argument('-w', '--write', action='store_true', help='Save successful results')

    args = parser.parse_args()

    if os.getuid() != 0:
        logger.error("Error: Run script as root (sudo)")
        sys.exit(1)

    if not InterfaceManager.set_interface_state(args.interface, down=False):
        logger.error(f"Unable to bring up interface {args.interface}")
        sys.exit(1)

    try:
        scanner = WiFiScanner(args.interface)
        targets = [args.bssid] if args.bssid else scanner.prompt_network()

        for target_bssid in targets:
            logger.info(f"Processing target: {target_bssid}")
            try:
                NetworkAddress(target_bssid)
            except ValueError as e:
                logger.error(f"Skipping invalid BSSID: {e}")
                continue

            with Companion(args.interface, save_result=args.write, bssid=target_bssid) as companion:
                pins = WPSpin().getSuggested(target_bssid)
                logger.info(f"Generated {len(pins)} candidate PINs for testing.")
                
    except KeyboardInterrupt:
        logger.warning("\nAborted by user.")
    finally:
        # Залишаємо інтерфейс піднятим або за потреби повертаємо стан
        pass