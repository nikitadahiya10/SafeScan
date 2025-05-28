import os                       
import hashlib
import mysql.connector
from flask import Flask, jsonify, request               #for web api
from flask_cors import CORS                              #allow communication bw web app or backend 
import time
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor              #for multithreading
import math
import subprocess                              #for running system cmd
import platform                               #System/platform-related info

app = Flask(__name__)                  #creating flask app
CORS(app)                             #allow requests from other domains(frontend & backend link)


#for controlling scan cancellation
stop_scan = False                       #initally false, true=when scan needs to stop

#db connection
def get_db_connection():
    return mysql.connector.connect(       
        host="localhost",
        user="root",
        password="09871",
        database="safescan"
    )

#load malware data from db
def load_malware_data():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()                   #object to run sql queries on db
        cursor.execute("SELECT hash, malware_name, threat_level FROM virus_hashes")
        data = {row[0]: (row[1], row[2]) for row in cursor.fetchall()}
        conn.close()
        return data
    except Exception as e:
        print(f"Error in loading malware data: {e}")
        return {}


malware_data = load_malware_data()

#save scan results to db
def save_scan_result(scan_results):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "INSERT INTO scan_results (file_path, malware_name, threat_level) VALUES (%s, %s, %s)"
        cursor.executemany(query, scan_results)                #run a single query for multiple rows
        conn.commit()                        #permananetly save changes
        conn.close()
    except Exception as e:
        print(f"❌ Error saving scan results: {e}")

#calculating file hash SHA-256 hash
def calculate_hash(file_path):                 
    try:
        hasher = hashlib.sha256()                     #for updating data
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):                 #read 4KB chunks
                hasher.update(chunk)
        return hasher.hexdigest()                      #return file hash in string
    except:
        return None

#signatures with assigned weights
signatures = {
    "Trojan": [
        (b"CreateRemoteThread", 3), (b"VirtualAllocEx", 2), (b"WriteProcessMemory", 3),
        (b"OpenProcess", 2), (b"LoadLibraryA", 1), (b"WinExec", 2), (b"ShellExecuteA", 2),
        (b"URLDownloadToFileA", 2), (b"NtCreateThreadEx", 3), (b"SetThreadContext", 2),
        (b"AdjustTokenPrivileges", 1), (b"GetAsyncKeyState", 2), (b"keybd_event", 1),
        (b"mouse_event", 1), (b"InternetOpen", 1), (b"InternetOpenUrl", 1), (b"InternetReadFile", 1),
        (b"RegSetValueExA", 1), (b"OpenProcessToken", 1), (b"LookupPrivilegeValueA", 1),
        (b"CreateProcessA", 2), (b"NtQueryInformationProcess", 1), (b"NtUnmapViewOfSection", 1),
        (b"GetForegroundWindow", 1), (b"GetWindowTextA", 1), (b"SetWindowsHookExA", 2),
        (b"OpenThread", 1), (b"EnumProcesses", 1)
    ],
    "Worm": [
        (b"NetUserAdd", 2), (b"NetScheduleJobAdd", 2), (b"socket", 1), (b"send", 1), (b"recv", 1),
        (b"connect", 1), (b"WSASocketA", 1), (b"bind", 1), (b"listen", 1), (b"accept", 1),
        (b"CreateFileA", 1), (b"WriteFile", 2), (b"FindFirstFile", 1), (b"FindNextFile", 1),
        (b"NetShareAdd", 2), (b"ShellExecute", 2), (b"NetUserEnum", 1), (b"NetGroupAdd", 2),
        (b"WNetAddConnection2A", 1), (b"NetShareEnum", 1), (b"InternetConnectA", 1),
        (b"HttpSendRequestA", 1), (b"GetAdaptersInfo", 1), (b"gethostbyname", 1)
    ],
    "File Infector": [
        (b"WriteFile", 2), (b"CreateFileA", 2), (b"SetFileAttributes", 1), (b"MoveFileExA", 1),
        (b"CopyFile", 1), (b"FindFirstFileA", 1), (b"FindNextFileA", 1), (b"GetModuleFileNameA", 1),
        (b"GetStartupInfoA", 1), (b"SetFilePointer", 1), (b"ReadFile", 1),
        (b"MapViewOfFile", 1), (b"UnmapViewOfFile", 1), (b"SetEndOfFile", 1),
        (b"GetFileSize", 1), (b"WriteProcessMemory", 2), (b"GetTempPathA", 1), (b"ReplaceFileA", 1)
    ]
}


def calculate_entropy(file_path):          #randomness(compressed and encrypted)
    try:
        with open(file_path, "rb") as f:
            byte_arr = list(f.read())
            if len(byte_arr) == 0:
                return 0
            freq_list = [0] * 256
            for b in byte_arr:
                freq_list[b] += 1
            entropy = 0.0
            for freq in freq_list:
                if freq > 0:
                    p = freq / len(byte_arr)
                    entropy -= p * math.log2(p)
            size_kb = len(byte_arr) / 1024
            if size_kb > 500 and entropy > 8.5:    
                return entropy
            else:
                return None
    except Exception as e:
        print(f"Error in entropy calculation: {e}")
        return None

def check_behavior(file_path):
    behavior_score = 0
    matched_signatures = 0
    try:
        if not file_path.lower().endswith(('.exe', '.dll', '.sys', '.scr', '.bat')):
            return 0
        with open(file_path, 'rb') as f:
            content = f.read()                                #read full file content

        for category, patterns in signatures.items():
            for pattern, weight in patterns:
                if pattern in content:
                    matched_signatures += 1
                    #weight reduced slightly for balance
                    behavior_score += max(1, weight - 1)

        if matched_signatures < 5 or behavior_score < 15:
            return 0
        return behavior_score
    except Exception as e:
        print(f"Error during behavior check: {e}")
        return 0

def calculate_threat_level(score):
    if score < 0 or score > 50:
        return "Invalid Score"  

    if score >= 40:
        return "Critical"
    elif score >= 30:
        return "Very High"
    elif score >= 22:
        return "High"
    elif score >= 15:
        return "Moderate"
    elif score >= 10:
        return "Low"
    else:
        return "Safe"



def scan_file(file_path, infected_files):
    global stop_scan
    if stop_scan:
        return

    #whitelist through absolute paths
    whitelist_paths = [
    # Chrome
    os.path.join(os.getenv("ProgramFiles", "C:\\Program Files"), "Google", "Chrome", "Application", "chrome.exe"),
    os.path.join(os.getenv("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Google", "Chrome", "Application", "chrome.exe"),

    # GitHub Desktop
    os.path.join(os.getenv("LOCALAPPDATA", os.path.expandvars("C:\\Users\\%USERNAME%\\AppData\\Local")), "GitHubDesktop"),

    # BlueStacks
    os.path.join(os.getenv("ProgramData", "C:\\ProgramData"), "BlueStacks"),

    # Windows Defender
    os.path.join(os.getenv("ProgramFiles", "C:\\Program Files"), "Windows Defender", "MSASCui.exe"),

    # Microsoft Office (Word)
    os.path.join(os.getenv("ProgramFiles", "C:\\Program Files"), "Microsoft Office", "root", "Office16", "WINWORD.EXE"),

    # Mozilla Firefox
    os.path.join(os.getenv("ProgramFiles", "C:\\Program Files"), "Mozilla Firefox", "firefox.exe"),

    # Notepad
    os.path.join(os.getenv("SystemRoot", "C:\\Windows"), "System32", "notepad.exe"),

    # Calculator
    os.path.join(os.getenv("SystemRoot", "C:\\Windows"), "System32", "calc.exe"),

    # Command Prompt
    os.path.join(os.getenv("SystemRoot", "C:\\Windows"), "System32", "cmd.exe"),

    # File Explorer
    os.path.join(os.getenv("SystemRoot", "C:\\Windows"), "explorer.exe"),

    # Visual Studio Code
    os.path.join(os.getenv("LOCALAPPDATA", os.path.expandvars("C:\\Users\\%USERNAME%\\AppData\\Local")), "Programs", "Microsoft VS Code", "Code.exe"),

    # Python (default installation in AppData)
    os.path.join(os.getenv("LOCALAPPDATA", os.path.expandvars("C:\\Users\\%USERNAME%\\AppData\\Local")), "Programs", "Python", "Python311", "python.exe"),

     # Microsoft Office
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "Microsoft Office", "Office16", "WINWORD.EXE"),
    os.path.join(os.getenv("ProgramFiles(x86)", os.path.expandvars("C:\\Program Files (x86)")), "Microsoft Office", "Office16", "WINWORD.EXE"),

    # Microsoft OneDrive
    os.path.join(os.getenv("LOCALAPPDATA", os.path.expandvars("C:\\Users\\%USERNAME%\\AppData\\Local")), "Microsoft OneDrive", "OneDrive.exe"),
    os.path.join(os.getenv("LOCALAPPDATA", os.path.expandvars("C:\\Users\\%USERNAME%\\AppData\\Local")), "Microsoft OneDrive", "FileSyncClient.dll"),

    # Microsoft Visual Studio
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "Microsoft Visual Studio", "2019", "Community", "Common7", "IDE", "devenv.exe"),
    os.path.join(os.getenv("ProgramFiles(x86)", os.path.expandvars("C:\\Program Files (x86)")), "Microsoft Visual Studio", "2019", "Community", "Common7", "IDE", "devenv.exe"),

    # Microsoft Edge
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "Microsoft", "Edge", "Application", "msedge.exe"),
    os.path.join(os.getenv("ProgramFiles(x86)", os.path.expandvars("C:\\Program Files (x86)")), "Microsoft", "Edge", "Application", "msedge.exe"),

    # Microsoft Store Apps (WindowsApps folder)
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "WindowsApps", "Microsoft.AppInstaller_8wekyb3d8bbwe", "AppInstaller.exe"),

    # Skype
    os.path.join(os.getenv("ProgramFiles(x86)", os.path.expandvars("C:\\Program Files (x86)")), "Microsoft", "Skype for Desktop", "Skype.exe"),

    # Windows Defender (Antivirus)
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "Windows Defender", "MSASCui.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\Windows")), "System32", "MpCmdRun.exe"),

    # Windows System Files (System32)
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\Windows")), "System32", "cmd.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\Windows")), "System32", "explorer.exe"),

    # Windows Update
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\Windows")), "System32", "wuauclt.exe"),
    
     # McAfee WebAdvisor - downloadscan.dll
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "WebAdvisor", "x64", "downloadscan.dll"),

    # McAfee Browser Helper - browser_helper.dll
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "browser_helper.dll"),

    # McAfee DAD - mc-dad.exe
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "dad", "mc-dad.exe"),

    # McAfee Sec Installer - mc-sec-installer.exe
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "driver", "mc-sec-installer.exe"),

    # McAfee Browser Host - mc-extn-browserhost.exe
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "extnhost", "mc-extn-browserhost.exe"),

    # McAfee Extension Module - mc-extn-module.dll
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "mc-extn-module.dll"),

    # McAfee Analytics - mc-analytics.dll
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "mc-analytics.dll"),

    # McAfee Cloud SDK - mc-cloudsdk.dll
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "mc-cloudsdk.dll"),

    # McAfee DA - mc-da.dll
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "mc-da.dll"),


     os.path.join(os.getenv("LOCALAPPDATA"), r"BlueStacks X\Bridge\5.13.200.1028\HD-Bridge-Native.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"BlueStacks X\Bridge\5.13.200.1028\Qt5Core.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\nsis\nsis-resources-3.4.1\plugins\x86-ansi\nsis7z.dll"),
     os.path.join(os.getenv("LOCALAPPDATA"), r"Programs\Common\UiPath\UiPath.Common\24.12.100.38979\JavaSupport\ScreenScrapeJavaSupport.exe"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Programs\Common\UiPath\UiPath.Common\24.12.100.38979\libcurl_x86.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Programs\Highlight\d3dcompiler_47.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Programs\Highlight\resources\app.asar.unpacked\node_modules\@highlight\windows\build\tesseract54.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Programs\Highlight\resources\app.asar.unpacked\node_modules\sharp\build\Release\libvips-42.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\072684067\openssl-ia32\openssl.exe"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\072684067\openssl-ia32\libeay32.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\072684067\windows-10\ia32\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\072684067\windows-10\x64\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\072684067\windows-6\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\123620699\openssl-ia32\openssl.exe"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\123620699\openssl-ia32\libeay32.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\123620699\windows-10\ia32\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\123620699\windows-10\x64\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\123620699\windows-6\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\423972779\openssl-ia32\openssl.exe"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\423972779\openssl-ia32\libeay32.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\423972779\windows-10\ia32\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\423972779\windows-10\x64\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\423972779\windows-6\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\718517415\windows-10\ia32\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\718517415\windows-10\x64\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\718517415\windows-6\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\winCodeSign-2.6.0\windows-10\ia32\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\winCodeSign-2.6.0\windows-10\x64\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"electron-builder\Cache\winCodeSign\winCodeSign-2.6.0\windows-6\wintrust.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Microsoft\TeamsMeetingAdd-in\1.24.14501\x64\adal2-meetingaddin.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Microsoft\TeamsMeetingAdd-in\1.24.14501\x64\Microsoft.Applications.Telemetry.Windows.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Microsoft\TeamsMeetingAdd-in\1.24.14501\x64\OneAuth.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Microsoft\TeamsMeetingAdd-in\1.24.14501\x86\Microsoft.Applications.Telemetry.Windows.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Microsoft\TeamsMeetingAdd-in\1.24.14501\x86\OneAuth.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Package Cache\{1abbd55d-059a-4d1e-bdf1-35bb74697f5a}\python-3.13.1-amd64.exe"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Programs\bluestacks-services\d3dcompiler_47.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Programs\Common\UiPath\UiPath.Common\24.12.100.38979\BrowserExtension\UiPath.BrowserBridge.Portable\coreclr.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), r"Programs\Common\UiPath\UiPath.Common\24.12.100.38979\BrowserExtension\UiPath.BrowserBridge.Portable\mscordbi.dll"),


    # Windows System Files
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "uireng.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "UdiApiClient.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "twinui.pcshell.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "UIAutomationCore.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "UpdateAgent.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "urlmon.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "vds.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "vfluapriv.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "vmcompute.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "vmcompute.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "VSSVC.exe"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "vmwp.exe"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "wsecedit.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "Umi.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "user32.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "kernel32.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "advapi32.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "shell32.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "msvcrt.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "ntdll.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "comdlg32.dll"),
   os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "ole32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "userenv.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "msxml6.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "dpnsvr.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "winlogon.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "wininit.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "lsass.exe"),

    #windows SysWOW64 System Files
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "wsecedit.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "Umi.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "user32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "kernel32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "advapi32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "shell32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "msvcrt.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "ntdll.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "comdlg32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "ole32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "userenv.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "msxml6.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "dpnsvr.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "winlogon.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "wininit.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "lsass.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "authui.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "bcrypt.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "cabinet.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "clbcatq.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "crypt32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "cryptbase.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "dbghelp.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "dinput.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "dnsapi.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "dwmapi.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "ieframe.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "kernelbase.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "mspmsnsv.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "msasn1.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "msctf.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "msvcp_win.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "netapi32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "netplwiz.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "netsh.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "oleaut32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "odbc32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "odbc32r.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "powrprof.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "rpcss.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "scrrun.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "spwizeng.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "tapi32.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "urlmon.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "win32k.sys"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "wininet.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "apphelp.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "dbgeng.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "KernelBase.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "mfc140d.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "wininet.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "OneDriveSetup.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "MRT.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "MRT"),  # Directory where MPENGINE.DLL may exist
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "AcSpecfc.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "AcGenral.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "apphelp.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "dbgeng.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "KernelBase.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "mfc140d.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "SysWOW64", "msvbvm60.dll"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "Microsoft-Edge-WebView", "msedgewebview2.exe"),
    os.path.join(os.getenv("SystemRoot", os.path.expandvars("C:\\WINDOWS")), "System32", "Microsoft-Edge-WebView", "msedge.dll"),
    os.path.join(os.getenv("LOCALAPPDATA"), "Programs", "bluestacks-services", "BlueStacksServices.exe"),
    os.path.join("C:\\Program Files", "Common Files", "microsoft shared", "ClickToRun", "OfficeClickToRun.exe"),
    #Whitelist Electron Builder Cache Files (Windows)
    os.path.join(os.getenv("USERPROFILE"), "AppData", "Local", "electron-builder", "Cache", "winCodeSign", "718517415", "openssl-ia32", "openssl.exe"),
    os.path.join(os.getenv("USERPROFILE"), "AppData", "Local", "electron-builder", "Cache", "winCodeSign", "718517415", "openssl-ia32", "libeay32.dll"),
    os.path.join(os.getenv("USERPROFILE"), "AppData", "Local", "electron-builder", "Cache", "winCodeSign", "winCodeSign-2.6.0", "openssl-ia32", "openssl.exe"),
    os.path.join(os.getenv("USERPROFILE"), "AppData", "Local", "electron-builder", "Cache", "winCodeSign", "winCodeSign-2.6.0", "openssl-ia32", "libeay32.dll"),
    #whitelist Highlight.exe (if from a trusted source)
    os.path.join(os.getenv("USERPROFILE"), "AppData", "Local", "Programs", "Highlight", "Highlight.exe"),
    # Whitelist WebExHost.exe (if from a trusted source)
    os.path.join(os.getenv("USERPROFILE"), "AppData", "Local", "WebEx", "WebexHost.exe"),
    # McAfee OEM Subjob - mc-oem-subjob.exe
    os.path.join(os.getenv("ProgramFiles", os.path.expandvars("C:\\Program Files")), "McAfee", "wps", "1.27.184.1", "mc-oem-subjob.exe")
   ]
    
    #check if file path matches any whitelisted path
    if os.path.abspath(file_path) in [os.path.abspath(p) for p in whitelist_paths]:
        print(f"✅ Skipped (Whitelisted absolute path): {file_path}")
        return

    print(f"🔍 Scanning: {file_path}")

    file_hash = calculate_hash(file_path)
    

    #step 1: Signature checking
    if file_hash and file_hash in malware_data:
        malware_name, threat_level = malware_data[file_hash]
        infected_files.append({"file": file_path, "malware_name": malware_name, "threat_level": threat_level})
        save_scan_result([(file_path, malware_name, threat_level)])
        print(f"⚠️ Signature Match: {malware_name} in {file_path}")
        return

    #Step 2: Heuristic + Entropy
    behavior_score = check_behavior(file_path)
    entropy = calculate_entropy(file_path)

    entropy_score = 0
    if entropy:
        if entropy > 8.5:
            entropy_score = 7
        elif entropy > 8.0:
            entropy_score = 5
        elif entropy > 7.5:
            entropy_score = 3
        else:
            entropy_score = 1

    total_score = behavior_score + entropy_score
    threat_level = calculate_threat_level(total_score)

    if threat_level == "Safe":
        print(f"✅ File is SAFE: {file_path}")
    else:
        malware_name = f"Suspicious File (Behavior+Entropy)"
        if threat_level in ("Low", "Medium"):
            print(f"🟡 Manual Review Suggested: {file_path} ({threat_level})")
        else:
            infected_files.append({"file": file_path, "malware_name": malware_name, "threat_level": threat_level})
            save_scan_result([(file_path, malware_name, threat_level)])
            print(f"⚠️ Detected: {malware_name} ({threat_level}) in {file_path}")

    time.sleep(0.02)



#get system paths for scanning
def get_system_paths():
    user_home = os.path.join(os.getenv("HOMEDRIVE", "C:"), os.getenv("HOMEPATH", "Users"))
    common_paths = [
        os.path.join(user_home),  
        os.path.join(user_home, "Downloads"),  
        os.path.join(user_home, "Desktop"),  
        os.path.join(user_home, "AppData", "Roaming"),  
        os.path.join(user_home, "AppData", "Local"),  
        os.path.join(os.getenv("SystemRoot", "C:\\Windows"), "System32"),  
        os.path.join(os.getenv("SystemRoot", "C:\\Windows"), "SysWOW64"),  
        os.path.join(os.getenv("ProgramFiles", "C:\\Program Files")),  
        os.path.join(os.getenv("ProgramFiles(x86)", "C:\\Program Files (x86)"))  
    ]

    for drive in "DEFGHIJKLMNOPQRSTUVWXYZ":
        drive_path = f"{drive}:\\" 
        if os.path.exists(drive_path):
            common_paths.append(drive_path)
    return common_paths

#scan the directory
def scan_directory(directory, executor):
    infected_files = []
    futures = []                       #stores the background scan tasks 
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                try:
                    if entry.is_file():
                        if entry.path.lower().endswith(('.exe', '.dll', '.scr', '.bat', '.com', '.pif', '.vbs', '.js', '.cmd', '.lnk', '.sys')):
                            futures.append(executor.submit(scan_file, entry.path, infected_files))

                    elif entry.is_dir():
                        infected_files.extend(scan_directory(entry.path, executor))
                except PermissionError:
                    print(f"🚫 Skipping (Permission Denied): {entry.path}")
                except Exception as e:
                    print(f"⚠️ Error accessing {entry.path}: {e}")
        concurrent.futures.wait(futures)
    except PermissionError:
        print(f"🚫 Skipping Directory (Permission Denied): {directory}")
    return infected_files

#start full scan api
@app.route("/start-full-scan", methods=["GET"])
def start_full_scan():
    global stop_scan
    stop_scan = False
    infected_files = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        for path in get_system_paths():
            if os.path.exists(path):
                infected_files.extend(scan_directory(path, executor))

    if infected_files:
        return jsonify({"infected_files": infected_files})
    else:
        return jsonify({"message": "No Threats Found!"})


#quick scan Paths
def get_quick_scan_paths():
    user_home = os.path.expanduser("~")  # Current user home directory
    quick_paths = [
        os.path.join(user_home, "Downloads"),
        os.path.join(user_home, "Desktop"),
        os.path.join(user_home, "AppData", "Roaming"),
        os.path.join(user_home, "AppData", "Local"),
        os.path.join(user_home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(user_home, "AppData", "Local", "Temp")
    ]
    return quick_paths

#start quick scan API
@app.route("/start-quick-scan", methods=["GET"])
def start_quick_scan():
    global stop_scan
    stop_scan = False
    infected_files = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        for path in get_quick_scan_paths():
            if os.path.exists(path):
                infected_files.extend(scan_directory(path, executor))

    if infected_files:
        return jsonify({"infected_files": infected_files})
    else:
        return jsonify({"message": "No Threats Found!"})

#custom scan api
@app.route("/start-custom-scan", methods=["POST"])
def start_custom_scan():
    global stop_scan
    stop_scan = False

    data = request.json
    selected_path = data.get("path")

    if not selected_path or not os.path.exists(selected_path):
        return jsonify({"error": "Please enter a valid path!"}), 400

    infected_files = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        if os.path.isfile(selected_path):
            scan_file(selected_path, infected_files)
        elif os.path.isdir(selected_path):
            infected_files.extend(scan_directory(selected_path, executor))
        else:
            return jsonify({"error": "Invalid file or directory type!"}), 400

    if infected_files:
        return jsonify({"infected_files": infected_files})
    else:
        return jsonify({"message": "No Threats Found!"})

    
#cancel scan API 
@app.route("/stop-scan", methods=["POST"])
def stop_scan_api():
    global stop_scan
    stop_scan = True          #set cancel flag to True
    return jsonify({"message": "Scan cancelled successfully!"})
    

#fetch scan results for quarantine page
@app.route('/get-scan-results', methods=['GET'])
def get_scan_results():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT file_path, malware_name, threat_level, scan_date FROM scan_results ORDER BY scan_date DESC")
        scan_results = cursor.fetchall()
        conn.close()
        return jsonify({"scan_results": scan_results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/get_quarantine_files', methods=['GET'])
def get_quarantine_files():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, file_path, malware_name, threat_level, scan_date FROM scan_results ORDER BY scan_date DESC")
        quarantine_files = cursor.fetchall()
        conn.close()
        return jsonify({"quarantine_files": quarantine_files})  # JSON key properly likho
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '09871',
    'database': 'safescan'
}

@app.route('/delete_quarantine_file', methods=['POST'])
def delete_quarantine_file():
    data = request.get_json()
    file_path = data.get('file_path')

    if not file_path:
        return jsonify(success=False, message="No file path provided.")

    try:
        conn = mysql.connector.connect(**db_config)        #dictionary arg into values
        cursor = conn.cursor()

        print(f"[DEBUG] Attempting to delete DB record for file: {file_path}")

        cursor.execute("SELECT * FROM scan_results WHERE file_path = %s", (file_path,))
        file_record = cursor.fetchone()
        cursor.fetchall()

        if not file_record:
            return jsonify(success=False, message="File not found in the database.")

        cursor.execute("DELETE FROM scan_results WHERE file_path = %s", (file_path,))
        conn.commit()

        cursor.execute("SELECT * FROM scan_results WHERE file_path = %s", (file_path,))
        file_record_after_delete = cursor.fetchone()

        cursor.close()
        conn.close()

        if file_record_after_delete:
            return jsonify(success=False, message="Failed to delete file record.")
        return jsonify(success=True)

    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return jsonify(success=False, message="Database error")

    except Exception as e:
        print(f"General Error: {e}")
        return jsonify(success=False, message="Something went wrong")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
