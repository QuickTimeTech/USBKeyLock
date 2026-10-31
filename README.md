# 🛡️ USBKeyLock Pro (v2.0) — Hardware USB Security Suite for Windows & Linux

**USBKeyLock Pro** turns any standard USB flash drive into a cryptographic hardware security key ("dead man's switch") for your PC. When your verified USB key is unplugged or ejected, **USBKeyLock Pro** immediately protects your workstation—locking your screen, muting audio, hibernating, or executing an emergency shutdown.

Unlike traditional scripts that waste CPU cycles and prevent drives from sleeping by polling USB ports in a loop, **USBKeyLock Pro** uses a **100% event-driven architecture** (Windows WMI `Win32_VolumeChangeEvent` / Linux `udev` kernel sockets). It sits at **0% CPU usage** in your System Tray until the OS kernel broadcasts a hardware interrupt.

---

## ✨ What's New in v2.0 Pro

* **🌙 Modern Dark-Mode Dashboard (`CustomTkinter`):** Clean 3-tab interface (**USB Drives & Control**, **Authorized Keys**, and **Security Audit Log**) with live status badges.
* **🛡️ Anti-Clone Hardware Binding & Whitelisting:** Reads the physical USB drive's factory Volume Serial Number, combines it with a unique 256-bit machine salt, and writes a hidden `SHA-256` token (`.usb_key.txt`). Copying the file onto another USB stick will **not** work.
* **🚫 Key Revocation Manager:** Provision multiple USB keys (e.g., a primary key and a backup key). If you ever lose a USB stick, revoke its serial number in one click under the **Authorized Keys** tab so it can never be used on your PC again.
* **⏱️ Grace Period Countdown (Bump Protection):** Choose between **Instant (0s)**, **3 Seconds**, **5 Seconds**, or **10 Seconds**. If a grace period is enabled, an emergency red banner and audible alert warn you when the drive is unplugged—plug it back in before the countdown hits zero to cancel the lock!
* **⚡ 4 Configurable Unplug Action Modes:**
  1. **Lock Screen** (Native `LockWorkStation`)
  2. **Lock + Mute Audio** (Instantly mutes system media/calls and locks the screen)
  3. **Hibernate / Sleep PC** (Locks and suspends power state)
  4. **Force Shutdown (Dead Man's Switch)** (Executes immediate `shutdown /s /f /t 0`)
* **🚀 Start with Windows Toggle:** Built-in switch registers the app in Windows Startup (`HKCU\...\Run` with `--minimized`) so protection starts automatically in your System Tray when you log in.
* **📋 Tamper & Security Audit Log:** Records timestamped logs of all arm/disarm events, failed password attempts, key revocations, and lock triggers.

---

## 🚀 Quick Start Guide (For End Users — `.exe`)

1. **Launch `USBKeyLock.exe`:**
   * *Note: If Windows SmartScreen appears on first launch, click **More info** -> **Run anyway**.*
2. **Set Your Personal Disarm Password:**
   * Click **Set Password** in the bottom-right panel.
   * Enter the default password: **`admin`**
   * Enter and confirm your new personal password (salted and hashed with 100,000 iterations of `PBKDF2-HMAC-SHA256`).
3. **Provision Your USB Flash Drive:**
   * Plug in any USB flash drive and click **🔄 Refresh**.
   * Select your drive from the list and click **🔑 Setup Hardware Key**.
   * Confirm the prompt. Your USB drive will now show **`(✓ AUTH)`** and appear in the **Authorized Keys** tab.
4. **Choose Your Protection Settings:**
   * Select your preferred **Unplug Action Mode** (e.g., *Lock Screen* or *Lock + Mute Audio*).
   * Select your **Grace Period** (e.g., *Instant (0s)* or *3 Seconds*).
   * *(Optional)* Toggle **Start with Windows (Tray)** so the app launches automatically when you turn on your PC.
5. **Arm the Lock:**
   * Click **🛡️ Verify & Arm Lock** (or simply unplug and plug your USB stick back in with **Auto-Arm** enabled).
   * The app will minimize to your **Windows System Tray** (by the clock) with a **Green Padlock** icon.

---

## 🛠️ Building from Source (For Developers)

### Prerequisites
* Python 3.10+
* Windows 10 / 11 (or Linux with `udev`)

### 1. Install Dependencies
**Windows:**
```powershell
python -m pip install customtkinter pywin32 wmi psutil pystray Pillow pyinstaller
```

**Linux:**
```bash
python3 -m pip install customtkinter pyudev psutil pystray Pillow
```

### 2. Generate the Custom Application Icon (`app_icon.ico`)
```powershell
python -c "from PIL import Image, ImageDraw; img = Image.new('RGBA', (256, 256), (0, 0, 0, 0)); d = ImageDraw.Draw(img); d.rounded_rectangle((16, 16, 240, 240), radius=56, fill='#0F2537', outline='#107C41', width=12); d.arc((86, 56, 170, 140), start=180, end=0, fill='#FFFFFF', width=18); d.rounded_rectangle((68, 112, 188, 204), radius=18, fill='#107C41', outline='#FFFFFF', width=8); d.ellipse((116, 142, 140, 166), fill='#FFFFFF'); d.polygon([(122, 160), (134, 160), (138, 186), (118, 186)], fill='#FFFFFF'); img.save('app_icon.ico', format='ICO', sizes=[(256,256), (128,128), (64,64), (48,48), (32,32), (16,16)])"
```

### 3. Run from Source
```powershell
python main.py
```
*(Pass `--minimized` to launch directly into the System Tray: `python main.py --minimized`)*

### 4. Compile Standalone Windows `.exe`
```powershell
python -m PyInstaller --noconsole --onefile --icon="app_icon.ico" --add-data "app_icon.ico;." --collect-all customtkinter --hidden-import=wmi --hidden-import=pythoncom --hidden-import=pywintypes --hidden-import=pystray._win32 --name "USBKeyLock" main.py
```
Your standalone executable will be output to **`dist\USBKeyLock.exe`**.

---

## 🔐 File Locations & Security Storage

All configuration and audit files are stored per-user inside your OS Application Data directory:
* **Windows Config:** `%LOCALAPPDATA%\USBKeyLock\security_config.json`
* **Windows Audit Log:** `%LOCALAPPDATA%\USBKeyLock\security_audit.log`
* **Linux Config & Log:** `~/.config/usbkeylock/`
* **USB Stick Token:** `<USB_ROOT>\.usb_key.txt` (Marked with Windows `FILE_ATTRIBUTE_HIDDEN`)

---

## ❓ Troubleshooting & FAQ

* **How do I open the window when it's in the System Tray?**
  Look in the bottom-right corner of your Windows taskbar next to the clock (click the `^` arrow if hidden). Double-click the green/blue padlock icon or right-click it and select **Show Dashboard**.
* **What if I lose my USB flash drive?**
  Log into Windows normally with your Windows PIN/password, open **USBKeyLock Pro**, go to the **Authorized Keys** tab, select the lost USB drive, and click **🚫 Revoke Selected Key**.
* **What if I forget my Disarm Password?**
  Unplug your USB drive to trigger a lock (which disarms the current session), log back into Windows, and delete `%LOCALAPPDATA%\USBKeyLock\security_config.json` to reset the password back to `admin`.

---

## 📄 License
Distributed under the **MIT License**. Free for personal and commercial distribution.
