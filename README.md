# 🔒 USBKeyLock — Zero-Polling Hardware USB Security Key for Windows & Linux

**USBKeyLock** turns any standard USB flash drive into a physical hardware security token (like a ”dead man's switch”) for your computer. When your verified USB stick is unplugged or ejected, **USBKeyLock** instantaneously locks your workstation screen.

Unlike traditional scripts that waste CPU and prevent drives from sleeping by polling your USB ports every second, **USBKeyLock** uses a **100% event-driven architecture** (Windows WMI `Win32_VolumeChangeEvent` / Linux `udev` kernel sockets). It sits at **0% CPU usage** in your System Tray until the operating system kernel broadcasts a hardware event.

---

## ✨ Key Features

* **⚡ Zero-Polling (0% CPU Usage):** Sleeps silently in the background and reacts only to OS-level hardware arrival and removal interrupts.
* **🛡️ Anti-Clone Hardware Binding (SHA-256):** Reads the physical USB drive's factory Volume Serial Number and binds it to a hidden cryptographic signature (`.usb_key.txt`). Copying the key file onto a different USB stick will **not** work.
* **🔌 Zero-Click Auto-Arm:** Plug in your configured USB drive at any time and the app automatically verifies the hardware signature, arms the lock, and minimizes to the System Tray.
* **🔑 PBKDF2-HMAC-SHA256 Password Protection:** Disarming the lock or exiting the application while armed requires your password (salted and hashed with 100,000 iterations of SHA-256—no plain-text passwords are ever stored).
* **📥 Clean System Tray Integration:** Runs unobtrusively near your system clock with visual status indicators (**Blue** = Standby / Waiting for Key, **Green** = Armed).

---

## 🚀 Quick Start (For End Users — `.exe`)

1. Download and launch **`USBKeyLock.exe`**.
   *(Note: If Windows SmartScreen appears, click **More info** -> **Run anyway**).*
2. **Change the Default Password:**
   * Click **Set Password**.
   * Enter the default password: **`admin`**
   * Enter and confirm your new personal disarm password.
3. **Configure Your USB Flash Drive:**
   * Plug in any USB flash drive and click **Refresh List**.
   * Select your USB drive from the list and click **Setup Hardware Key**.
   * Confirm the prompt. A hidden, hardware-bound `.usb_key.txt` signature is written to your USB drive.
4. **Arm the Lock:**
   * Click **Verify & Arm Lock**.
   * The window will automatically hide to your **Windows System Tray** (bottom-right corner by the clock) with a **Green Padlock** icon.
5. **Test It:**
   * Unplug your USB flash drive. Your Windows screen will lock immediately!
   * Log back into Windows and plug the USB flash drive back in—**USBKeyLock** will automatically detect it and re-arm itself within half a second.

---

## 🛠️ Running from Source (For Developers)

### Prerequisites
* Python 3.10+
* Windows 10 / 11 (or Linux with `udev`)

### 1. Install Dependencies
 Create a `requirements.txt` or install directly via `pip`:

**Windows:**
```bash
python -m pip install pywin32 wmi psutil pystray Pillow
```

**Linux:**
```bash
python3 -m pip install pyudev psutil pystray Pillow
```

### 2. Run the Application
```bash
python main.py
```

### 3. Build a Standalone Windows `.exe`
To compile the script into a single, console-free executable using PyInstaller:

```powershell
python -m pip install pyinstaller
python -m PyInstaller --noconsole --onefile --hidden-import=wmi --hidden-import=pythoncom --hidden-import=pywintypes --hidden-import=pystray._win32 --name "USBKeyLock" main.py
```
The compiled executable will be generated inside `dist\USBKeyLock.exe`.

---

## 🔐 Security Architecture

| Component | Implementation Details |
| :--- | :--- |
| **USB Hardware Binding** | Reads hardware Volume Serial via `GetVolumeInformationW` (Win32 API) + 256-bit installation salt -> `SHA-256` digest stored in hidden `.usb_key.txt`. |
| **Password Storage** | `hashlib.pbkdf2_hmac('sha256', password, 256-bit_salt, 100000)` verified via constant-time `hmac.compare_digest()`. Stored in `%LOCALAPPDATA%\USBKeyLock\security_config.json`. |
| **Hardware Event Listener** | Windows WMI `Win32_VolumeChangeEvent` (`EventType=2` Arrival, `EventType=3` Removal). |
| **Workstation Lock** | Native Win32 API `ctypes.windll.user32.LockWorkStation()`. |

---

## ❓ Troubleshooting & FAQ

* **What if I lose my USB stick while the lock is armed?**
  Your screen will lock when the USB is removed. Simply log back into Windows using your normal Windows password/PIN. The app automatically disarms once it triggers a lock screen.
* **What if I forget my Disarm Password?**
  Unplugging the USB stick will lock your PC and disarm the monitor. To reset your disarm password back to `admin`, delete `%LOCALAPPDATA%\USBKeyLock\security_config.json` and re-provision your USB key.
* **Where is the System Tray icon?**
  Look in the bottom-right corner of your Windows taskbar next to the clock (click the little upward arrow `^` if Windows hides extra icons). Double-click the padlock icon to open the main window.

---

## 📄 License
Distributed under the **MIT License**. Free for personal and commercial use.
