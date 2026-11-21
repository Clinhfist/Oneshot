OneShot (Multi-Target Wrapper + OneShotPin)
OneShot — це набір інструментів для аудиту безпеки WPS-мереж без необхідності переводити бездротовий інтерфейс у режим моніторингу. Репозиторій містить базовий скрипт oneshot.py, багатоцільову обгортку main.py з автоматизацією етапів перевірки, захистом від «зависання» на заблокованих/повільних точках доступу та збереженням результатів у crack.json, а також кросплатформний інсталятор залежностей install_deps.py.
> Примітка: Використовуйте інструмент лише у межах авторизованого тестування власних або дозволених для аудиту мереж.
> 
Можливості
 * Багатоцільовий пайплайн (main.py):
   * Сканування WPS-мереж через oneshot.py із пріоритетним виведенням підсвічених (GREEN) цілей.
   * Гнучкий вибір цілей: діапазон (1-3), перелік (1 2 4) або всі мережі (0).
   * Послідовне проходження етапів для кожної точки доступу: Pixie Dust (-K) (за потреби з --pixie-force / -F), Bruteforce (-B) із заданою затримкою та опціонально PBC (--pbc).
   * Анти-зависання (run_stage): автоматичний пропуск стадії при повторенні того самого PIN, виявленні WPS Locked / rate limiting, серії помилок WPS-FAIL / WSC NACK або перевищенні таймауту.
   * Збереження знайдених даних у crack.json та зручний перегляд історії через -c / --cracks.
   * Управління станом інтерфейсу та NetworkManager (nmcli) під час роботи й відновлення з'єднання після завершення або через -r / --restore.
 * Автоматизація встановлення залежностей (install_deps.py):
   * Автоматичне визначення пакетного менеджера Linux (apt, pacman, dnf, zypper, apk) та встановлення системних утиліт.
   * Встановлення Python-залежностей із requirements.txt (за наявності), підтримка --dry-run та перевірка середовища.
 * Базовий рушій (oneshot.py):
   * Атака Pixie Dust без переходу в monitor mode.
   * Вбудований генератор WPS PIN (MAC-алгоритми та статичні PIN для поширених вендорів).
   * Онлайн-брутфорс WPS із розбиттям на дві половини PIN та збереженням сесій.
   * Сканер мереж на базі iw із підсвічуванням та підтримкою списку вразливих пристроїв (vulnwsc.txt).
Вимоги
 * Python 3.6+
 * Права root (sudo) для роботи з мережевими інтерфейсами та wpa_supplicant
 * Системні утиліти:
   * wpa_supplicant (зібраний із підтримкою WPS, CONFIG_WPS=y)
   * pixiewps
   * iw
   * ip (iproute2)
   * nmcli (NetworkManager) — опціонально для керування станом managed та відновлення Wi-Fi
Встановлення
1. Клонування репозиторію
git clone https://github.com/Clinhfist/Oneshot.git
cd Oneshot

2. Встановлення системних залежностей
Автоматично через install_deps.py (рекомендовано для Linux)
python3 install_deps.py

Доступні прапори для install_deps.py:
 * --dry-run — лише показати команди без їх виконання.
 * --dir /шлях/до/проєкту — вказати директорію проєкту для пошуку requirements.txt.
> Примітка щодо Windows: Оскільки main.py та oneshot.py спираються на pty, select і системні утиліти Linux (ip, iw, wpa_supplicant, nmcli), нативна робота на Windows не підтримується. Використовуйте нативний Linux або WSL2 із прокинутим USB Wi-Fi адаптером.
> 
Вручну за дистрибутивом
Arch Linux / CachyOS:
sudo pacman -S wpa_supplicant pixiewps iw iproute2 networkmanager python

Debian / Ubuntu:
sudo apt update
sudo apt install -y wpasupplicant pixiewps iw iproute2 network-manager python3

Alpine Linux / Termux (з root):
# Alpine
sudo apk add python3 wpa_supplicant pixiewps iw iproute2

# Termux (потребує root)
pkg install -y root-repo tsu python wpa-supplicant pixiewps iw openssl

Використання main.py
Аргументи командного рядка
usage: main.py [-h] [-c] [-i INTERFACE] [-d DELAY] [-F] [-v] [-r] [--pbc]

Multi-target pipeline wrapper for oneshot.py

options:
  -h, --help            show this help message and exit
  -c, --cracks          Print formatted results from crack.json
  -i, --interface INTERFACE
                        Wireless interface
  -d, --delay DELAY     Delay between pin attempts for bruteforce (default: 2.0)
  -F, --pixie-force     Use --pixie-force flag
  -v, --verbose         Pass -v to oneshot.py for verbose output
  -r, --restore         Restore Wi-Fi interface to managed mode and re-enable networking
  --pbc                 Include Push Button Connect stage if needed

Приклади запусків
Запуск багатоцільового сканування та пайплайну на інтерфейсі wlan0:
sudo python3 main.py -i wlan0

Запуск із --pixie-force, затримкою 1.5 с між спробами брутфорсу та додатковим етапом --pbc:
sudo python3 main.py -i wlan0 -F -d 1.5 --pbc

Детальний вивід (verbose):
sudo python3 main.py -i wlan0 -v

Перегляд збережених результатів із crack.json:
python3 main.py -c

Відновлення інтерфейсу в managed-режим та увімкнення Wi-Fi:
sudo python3 main.py -i wlan0 -r

Формат crack.json
Успішні результати автоматично додаються до crack.json у вигляді масиву об'єктів:
[
  {
    "essid": "Example_AP",
    "bssid": "00:11:22:33:44:55",
    "pin": "12345670",
    "pass": "secret_password",
    "method": "Pixie Dust (-K)"
  }
]

Використання oneshot.py напряму
Якщо потрібно запустити окрему атаку без багатоцільової обгортки:
# Сканування та інтерактивний вибір цілі + Pixie Dust
sudo python3 oneshot.py -i wlan0 -K

# Pixie Dust за конкретним BSSID із записом у reports/stored.*
sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K -w

# Онлайн-брутфорс із початковим PIN
sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -B -p 1234

# WPS Push Button Connect
sudo python3 oneshot.py -i wlan0 --pbc

Типові проблеми та вирішення
 * Інтерфейс заблоковано (RF-kill): виконайте sudo rfkill unblock wifi.
 * Інтерфейс зайнятий або NetworkManager перехоплює керування: використайте sudo python3 main.py -i <iface> -r для повернення інтерфейсу в managed-режим і увімкнення радіомодуля.
 * Пристрої MediaTek SoC (наприклад, на Android/Linux з /dev/wmtWifi): у oneshot.py доступний прапор --mtk-wifi (попередньо вимкніть Wi-Fi у системних налаштуваннях).
Подяки
 * rofl0r — за початкову реалізацію OneShotPin.
 * drygdryg — за розвиток та модифікації OneShot.
 * Wiire — за розробку pixiewps.
 * Monohrom — за тестування, ідеї та допомогу у виявленні помилок.
