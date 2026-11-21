# OneShot

**Multi-Target Wrapper + OneShotPin**

OneShot — це набір інструментів для аудиту безпеки WPS-мереж без необхідності переводити бездротовий інтерфейс у режим моніторингу (Monitor Mode)[span_0](start_span)[span_0](end_span).

Репозиторій містить модернізований базовий скрипт `oneshot.py`, багатоцільову обгортку `main.py` з автоматизацією етапів перевірки, захистом від зависання на заблокованих або повільних точках доступу та збереженням результатів у `crack.json`[span_1](start_span)[span_1](end_span).

Також до складу входять кросплатформний інсталятор залежностей `install_deps.py` і файл `requirements.txt`[span_2](start_span)[span_2](end_span).

> [!WARNING]
> Використовуйте інструмент виключно в межах авторизованого тестування власних мереж або мереж, на аудит яких ви маєте дозвіл[span_3](start_span)[span_3](end_span).

---

## 📑 Зміст

- [Можливості](#-можливості)
- [Вимоги](#-вимоги)
- [Встановлення](#-встановлення)
- [Використання main.py](#-використання-mainpy)
- [Формат crack.json](#-формат-crackjson)
- [Використання oneshot.py](#-використання-oneshotpy)
- [Типові проблеми та вирішення](#-типові-проблеми-та-вирішення)
- [Подяки](#-подяки)

---

## 🚀 Можливості

### 1. Багатоцільовий пайплайн (`main.py`)

- **Автоматичне сканування:** пошук WPS-мереж через `oneshot.py` із пріоритетним виведенням підсвічених (`GREEN`) цілей[span_4](start_span)[span_4](end_span).
- **Гнучкий вибір цілей:** підтримка діапазону (`1-3`), переліку (`1 2 4`) або всіх доступних мереж (`0`)[span_5](start_span)[span_5](end_span).
- **Послідовний пайплайн:** виконання етапів для кожної точки доступу[span_6](start_span)[span_6](end_span):
  - Pixie Dust (`-K`), за потреби з `--pixie-force` (`-F`)[span_7](start_span)[span_7](end_span).
  - Bruteforce (`-B`) із заданою затримкою[span_8](start_span)[span_8](end_span).
  - Push Button Connect (`--pbc`), за потреби[span_9](start_span)[span_9](end_span).
- **Anti-Hang Protection (`run_stage`):** автоматичний пропуск поточної стадії у разі[span_10](start_span)[span_10](end_span):
  - Повторення того самого PIN[span_11](start_span)[span_11](end_span).
  - Виявлення `WPS Locked` або rate limiting[span_12](start_span)[span_12](end_span).
  - Серії помилок `WPS-FAIL` / `WSC NACK`[span_13](start_span)[span_13](end_span).
  - Перевищення встановленого таймауту[span_14](start_span)[span_14](end_span).
- **Збереження результатів:** автоматичний запис знайдених даних у `crack.json`[span_15](start_span)[span_15](end_span).
- **Історія результатів:** зручний перегляд збережених даних через `-c` / `--cracks`[span_16](start_span)[span_16](end_span).
- **Керування мережевим інтерфейсом:** інтеграція з NetworkManager (`nmcli`), управління станом інтерфейсу та відновлення з'єднання після завершення роботи або через `-r` / `--restore`[span_17](start_span)[span_17](end_span).

### 2. Оновлений базовий рушій (`oneshot.py`)

- **Pixie Dust:** реалізація атаки без переходу в Monitor Mode[span_18](start_span)[span_18](end_span).
- **WPS PIN Generator:** вбудований генератор PIN на основі MAC-алгоритмів і статичних PIN поширених виробників із валідацією MAC-адрес[span_19](start_span)[span_19](end_span).
- **Online Bruteforce:** онлайн-брутфорс WPS із розбиттям PIN на дві половини, монотонним вимірюванням інтервалів (`time.monotonic`) і збереженням сесій[span_20](start_span)[span_20](end_span).
- **Network Scanner:** сканування мереж на базі `iw`, табличне форматування через `wcwidth`, кольорове підсвічування та підтримка списку вразливих пристроїв (`vulnwsc.txt`)[span_21](start_span)[span_21](end_span).
- **Безпечне виконання процесів:** запуск зовнішніх утиліт без `shell=True`[span_22](start_span)[span_22](end_span).
- **Очищення ресурсів:** гарантоване видалення тимчасових директорій і UNIX-сокетів під час завершення роботи[span_23](start_span)[span_23](end_span).

### 3. Автоматизація встановлення залежностей (`install_deps.py` + `requirements.txt`)

- **Автоматичне визначення пакетного менеджера Linux:**[span_24](start_span)[span_24](end_span)
  - `apt`[span_25](start_span)[span_25](end_span)
  - `pacman`[span_26](start_span)[span_26](end_span)
  - `dnf`[span_27](start_span)[span_27](end_span)
  - `zypper`[span_28](start_span)[span_28](end_span)
  - `apk`[span_29](start_span)[span_29](end_span)
- **Автоматичне встановлення** системних утиліт і Python-пакета `wcwidth`[span_30](start_span)[span_30](end_span).
- **Встановлення Python-залежностей** із `requirements.txt`[span_31](start_span)[span_31](end_span).
- **Режим попереднього перегляду команд** (`--dry-run`)[span_32](start_span)[span_32](end_span).
- **Діагностика системного середовища**[span_33](start_span)[span_33](end_span).

---

## 📋 Вимоги

| Компонент | Вимога |
| :--- | :--- |
| Python | `3.6+` |
| Привілеї | `root` / `sudo` |
| Операційна система | Linux |
| WPS | `wpa_supplicant` із підтримкою WPS |

### Python-залежності

| Пакет | Версія | Призначення |
| :--- | :--- | :--- |
| `wcwidth` | `>= 0.2.5` | Коректне вирівнювання таблиць у терміналі |

### Системні залежності

| Утиліта | Призначення |
| :--- | :--- |
| `wpa_supplicant` | Робота з WPS (потрібен `CONFIG_WPS=y`) |
| `pixiewps` | Обробка Pixie Dust |
| `iw` | Керування та сканування Wi-Fi |
| `ip` (`iproute2`) | Управління мережевими інтерфейсами |
| `nmcli` (`NetworkManager`) | Опціональне керування станом мережі та відновлення Wi-Fi |

---

## 📦 Встановлення

### 1. Клонування репозиторію

```bash
git clone [https://github.com/Clinhfist/Oneshot.git](https://github.com/Clinhfist/Oneshot.git)
cd Oneshot

2. Встановлення системних і Python-залежностей
Рекомендований спосіб для Linux:
python3 install_deps.py

Доступні аргументи install_deps.py:
| Аргумент | Опис |
|---|---|
| --dry-run | Показати команди без їх виконання |
| --dir PATH | Вказати директорію проєкту для пошуку requirements.txt |
Встановлення вручну
<details>
<summary><b>Arch Linux / CachyOS</b></summary>
sudo pacman -S wpa_supplicant pixiewps iw iproute2 networkmanager python python-wcwidth

</details>
<details>
<summary><b>Debian / Ubuntu</b></summary>
sudo apt update
sudo apt install -y wpasupplicant pixiewps iw iproute2 network-manager python3 python3-wcwidth

</details>
<details>
<summary><b>Fedora / RHEL (dnf)</b></summary>
sudo dnf install -y wpa_supplicant pixiewps iw iproute-tc python3 python3-wcwidth

</details>
<details>
<summary><b>Alpine Linux</b></summary>
sudo apk add python3 py3-wcwidth wpa_supplicant pixiewps iw iproute2

</details>
<details>
<summary><b>Termux (потребує root)</b></summary>
pkg install -y root-repo tsu python wpa-supplicant pixiewps iw openssl
pip install -r requirements.txt

</details>
Встановлення Python-залежностей окремо
Якщо системні утиліти вже встановлені:
pip install -r requirements.txt

> [!NOTE]
> Windows: нативна робота не підтримується, оскільки main.py та oneshot.py використовують pty, select, UNIX-сокети та системні утиліти Linux (ip, iw, wpa_supplicant, nmcli).
> Для роботи використовуйте нативний Linux або WSL2 із прокинутим USB Wi-Fi адаптером.
> 
⚙️ Використання main.py
Аргументи командного рядка
usage: main.py [-h] [-c] [-i INTERFACE] [-d DELAY] [-F] [-v] [-r] [--pbc]

Multi-target pipeline wrapper for oneshot.py

options:
  -h, --help            show this help message and exit
  -c, --cracks          Print formatted results from crack.json
  -i, --interface       Wireless interface
  -d, --delay DELAY     Delay between PIN attempts (default: 2.0)
  -F, --pixie-force     Use --pixie-force flag
  -v, --verbose         Pass -v to oneshot.py
  -r, --restore         Restore Wi-Fi interface to managed mode
  --pbc                 Include Push Button Connect stage if needed

Приклади запуску
Базовий запуск багатоцільового сканування:
sudo python3 main.py -i wlan0

Запуск із Pixie Force, затримкою 1.5 секунди та PBC:
sudo python3 main.py -i wlan0 -F -d 1.5 --pbc

Детальний вивід (Verbose):
sudo python3 main.py -i wlan0 -v

Перегляд збережених результатів:
python3 main.py -c

Відновлення мережевого інтерфейсу:
sudo python3 main.py -i wlan0 -r

💾 Формат crack.json
Успішні результати автоматично додаються до crack.json у форматі JSON-масиву об'єктів.
Структура запису:
[
  {
    "essid": "Example_AP",
    "bssid": "00:11:22:33:44:55",
    "pin": "12345670",
    "pass": "secret_password",
    "method": "Pixie Dust (-K)"
  }
]

🔧 Використання oneshot.py
Якщо потрібно запустити окрему операцію без використання багатоцільової обгортки main.py:
Сканування та інтерактивний вибір цілі + Pixie Dust:
sudo python3 oneshot.py -i wlan0 -K

Робота з конкретним BSSID із записом у reports/stored.*:
sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K -w

Online Bruteforce із початковим PIN:
sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234

WPS Push Button Connect:
sudo python3 oneshot.py -i wlan0 --pbc

🛠️ Типові проблеми та вирішення
| Проблема | Рішення |
|---|---|
| Інтерфейс заблоковано (RF-kill) | sudo rfkill unblock wifi |
| Інтерфейс зайнятий або NetworkManager перехоплює керування | sudo python3 main.py -i <iface> -r |
| ModuleNotFoundError: No module named 'wcwidth' | python3 install_deps.py або встановлення python-wcwidth / python3-wcwidth через пакетний менеджер |
| Пристрої MediaTek SoC (/dev/wmtWifi) | Використовуйте прапор --mtk-wifi у oneshot.py, попередньо вимкнувши Wi-Fi у системних налаштуваннях |
🙏 Подяки
Особлива подяка розробникам та учасникам, чия робота зробила цей проєкт можливим:
| Автор | Внесок |
|---|---|
| rofl0r | Початкова реалізація OneShotPin |
| drygdryg | Розвиток та модифікації OneShot |
| Wiire | Розробка pixiewps |
| Monohrom | Тестування, ідеї та допомога у виявленні помилок |
<p align="center">
<b>OneShot</b>

<sub>WPS Security Auditing Toolkit</sub>
</p>
