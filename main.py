import ctypes
import hashlib
import hmac
import json
import os
import platform
import secrets
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from PIL import Image, ImageDraw
import psutil
import pystray

OS_TYPE = platform.system()
APP_NAME = "USBKeyLock"
APP_VERSION = "1.0.0"

if OS_TYPE == "Windows":
  import pythoncom
  import pywintypes
  import wmi
elif OS_TYPE == "Linux":
  import pyudev


# --- PROPER OS APPDATA STORAGE FOR DISTRIBUTION ---
def get_appdata_dir() -> str:
  """Returns a user-writable OS application data directory."""
  if OS_TYPE == "Windows":
    base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    path = os.path.join(base, APP_NAME)
  else:
    path = os.path.join(os.path.expanduser("~"), ".config", APP_NAME.lower())
  os.makedirs(path, exist_ok=True)
  return path


CONFIG_FILE = os.path.join(get_appdata_dir(), "security_config.json")
KEY_FILENAME = ".usb_key.txt"
PBKDF2_ITERATIONS = 100000
FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_NORMAL = 0x80


class SecurityConfig:
  """Manages per-installation cryptographic salts and password hashes."""

  def __init__(self):
    self.hw_salt = ""
    self.pw_salt = ""
    self.password_hash = ""
    self.is_default_pw = True
    self.load()

  def hash_password(self, plain_password: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        plain_password.strip().encode("utf-8"),
         bytes.fromhex(self.pw_salt),
        PBKDF2_ITERATIONS,
    )
    return dk.hex()

  def load(self):
    if os.path.isfile(CONFIG_FILE):
      try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
          data = json.load(f)
          self.hw_salt = data["hw_salt"]
          self.pw_salt = data["pw_salt"]
          self.password_hash = data["password_hash"]
          self.is_default_pw = data.get("is_default_pw", False)
          return
      except Exception:
        pass

    # First run on this PC: generate unique cryptographic salts for this user
    self.hw_salt = secrets.token_hex(32)
    self.pw_salt = secrets.token_hex(32)
    self.password_hash = self.hash_password("admin")
    self.is_default_pw = True
    self.save()

  def save(self):
    data = {
        "hw_salt": self.hw_salt,
        "pw_salt": self.pw_salt,
        "password_hash": self.password_hash,
        "is_default_pw": self.is_default_pw,
    }
    try:
      with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    except Exception:
      pass


class USBMonitorApp:

  def __init__(self, root):
    self.root = root
    self.root.title(f"{APP_NAME} v{APP_VERSION} — Hardware Security Monitor")
    self.root.geometry("630x410")
    self.root.resizable(False, False)

    self.config = SecurityConfig()
    self.monitoring = False
    self.monitored_device = None
    self.app_running = True
    self.tray_icon = None

    self.root.protocol("WM_DELETE_WINDOW", self.on_close_window)

    self._build_ui()
    self.refresh_drives()

    threading.Thread(target=self._start_os_event_bus, daemon=True).start()
    self.root.after(600, self._check_existing_drives_for_auto_arm)

  def _build_ui(self):
    main_frame = ttk.Frame(self.root, padding="15")
    main_frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(
        main_frame,
        text="Connected Removable USB Drives (with Hardware ID):",
        font=("Segoe UI", 10, "bold"),
    ).pack(anchor=tk.W, pady=(0, 5))

    list_frame = ttk.Frame(main_frame)
    list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

    scrollbar = ttk.Scrollbar(list_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    self.drive_listbox = tk.Listbox(
        list_frame,
        font=("Consolas", 10),
        height=7,
        yscrollcommand=scrollbar.set,
        selectmode=tk.SINGLE,
    )
    self.drive_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.config(command=self.drive_listbox.yview)

    self.auto_arm_var = tk.BooleanVar(value=True)
    auto_arm_cb = ttk.Checkbutton(
        main_frame,
        text=(
            "Auto-Arm automatically when a valid Hardware Key USB is plugged in"
            " (Zero-Click Mode)"
        ),
        variable=self.auto_arm_var,
    )
    auto_arm_cb.pack(anchor=tk.W, pady=(6, 2))

    btn_frame = ttk.Frame(main_frame)
    btn_frame.pack(fill=tk.X, pady=8)

    self.refresh_btn = ttk.Button(
        btn_frame, text="Refresh List", command=self.refresh_drives
    )
    self.refresh_btn.pack(side=tk.LEFT, padx=(0, 6))

    self.setup_btn = ttk.Button(
        btn_frame, text="Setup Hardware Key", command=self.provision_usb_key
    )
    self.setup_btn.pack(side=tk.LEFT, padx=(0, 6))

    self.monitor_btn = ttk.Button(
        btn_frame,
        text="Verify & Arm Lock",
        command=self.toggle_monitoring,
    )
    self.monitor_btn.pack(side=tk.LEFT, padx=(0, 6))

    self.pw_btn = ttk.Button(
        btn_frame, text="Set Password", command=self.change_password_dialog
    )
    self.pw_btn.pack(side=tk.LEFT, padx=(0, 6))

    self.hide_btn = ttk.Button(
        btn_frame,
        text="Hide to Tray",
        command=self.hide_to_tray,
    )
    self.hide_btn.pack(side=tk.RIGHT)

    default_msg = (
        "Status: Waiting for USB Key (Auto-Arm Active | Default pw: 'admin')"
        if self.config.is_default_pw
        else "Status: Waiting for USB Key (Auto-Arm Active | Custom password set)"
    )
    self.status_var = tk.StringVar(value=default_msg)
    status_label = ttk.Label(
        main_frame,
        textvariable=self.status_var,
        foreground="gray",
        font=("Segoe UI", 9),
    )
    status_label.pack(anchor=tk.W, pady=(5, 0))

  # --- HARDWARE SERIAL NUMBER & SHA-256 BINDING ---
  def get_drive_hardware_serial(self, device: str, mountpoint: str) -> str:
    if OS_TYPE == "Windows":
      vol_name_buf = ctypes.create_unicode_buffer(261)
      fs_name_buf = ctypes.create_unicode_buffer(261)
      serial_num = ctypes.c_ulong(0)
      max_comp_len = ctypes.c_ulong(0)
      fs_flags = ctypes.c_ulong(0)

      root_path = mountpoint if mountpoint.endswith("\\") else mountpoint + "\\"
      res = ctypes.windll.kernel32.GetVolumeInformationW(
          ctypes.c_wchar_p(root_path),
          vol_name_buf,
          ctypes.sizeof(vol_name_buf),
          ctypes.byref(serial_num),
          ctypes.byref(max_comp_len),
          ctypes.byref(fs_flags),
          fs_name_buf,
          ctypes.sizeof(fs_name_buf),
      )
      if res != 0 and serial_num.value != 0:
        return f"{serial_num.value:08X}"
      return "UNKNOWN_WIN_SERIAL"

    elif OS_TYPE == "Linux":
      try:
        out = subprocess.check_output(
            ["lsblk", "-no", "UUID", device], text=True
        ).strip()
        return out if out else "UNKNOWN_LINUX_UUID"
      except Exception:
        return "UNKNOWN_LINUX_UUID"

    return "UNSUPPORTED_OS_SERIAL"

  def generate_hardware_token(self, device: str, mountpoint: str) -> str:
    hw_serial = self.get_drive_hardware_serial(device, mountpoint)
    payload = f"{hw_serial}::{self.config.hw_salt}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

  # --- PASSWORD VERIFICATION ---
  def verify_disarm_password(self) -> bool:
    self._restore_window()
    entered_pw = simpledialog.askstring(
        "Password Required",
        "Enter current password:",
        show="*",
        parent=self.root,
    )
    if entered_pw is None:
      return False

    entered_hash = self.config.hash_password(entered_pw)
    if hmac.compare_digest(entered_hash, self.config.password_hash):
      return True
    else:
      messagebox.showerror("Access Denied", "Incorrect password!")
      return False

  def change_password_dialog(self):
    if not self.verify_disarm_password():
      return

    new_pw = simpledialog.askstring(
        "Set New Password",
        "Enter your new disarm password:",
        show="*",
        parent=self.root,
    )
    if not new_pw:
      return

    confirm_pw = simpledialog.askstring(
        "Confirm Password",
        "Re-enter your new disarm password:",
        show="*",
        parent=self.root,
    )
    if new_pw != confirm_pw:
      messagebox.showerror("Mismatch", "Passwords did not match.")
      return

    self.config.password_hash = self.config.hash_password(new_pw)
    self.config.is_default_pw = False
    self.config.save()

    messagebox.showinfo(
        "Password Saved",
        "Your new disarm password has been hashed and saved!",
    )
    self.status_var.set("Status: Custom disarm password saved and active!")

  # --- SYSTEM TRAY MANAGEMENT ---
  def _create_tray_image(self, armed: bool):
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    bg_color = "#107C41" if armed else "#2B579A"
    draw.ellipse((4, 4, 60, 60), fill=bg_color, outline="#FFFFFF", width=3)
    draw.arc((22, 14, 42, 34), start=180, end=0, fill="white", width=4)
    draw.rectangle((18, 28, 46, 48), fill="white")
    return image

  def hide_to_tray(self):
    self.root.withdraw()
    self._stop_tray_icon()

    image = self._create_tray_image(armed=self.monitoring)
    tooltip = (
        f"USB Lock ARMED ({self.monitored_device})"
        if self.monitoring
        else "USB Lock Standby (Waiting for Key)"
    )

    menu_items = [
        pystray.MenuItem("Show Window", self._tray_show_window, default=True)
    ]
    if self.monitoring:
      menu_items.append(pystray.MenuItem("Disarm Lock", self._tray_disarm))
    menu_items.append(pystray.MenuItem("Exit App", self._tray_exit))

    self.tray_icon = pystray.Icon(
        "usb_lock_monitor",
        image,
        tooltip,
        pystray.Menu(*menu_items),
    )
    threading.Thread(target=self.tray_icon.run, daemon=True).start()

  def _stop_tray_icon(self):
    if self.tray_icon is not None:
      self.tray_icon.stop()
      self.tray_icon = None

  def _tray_show_window(self, icon=None, item=None):
    self._stop_tray_icon()
    self.root.after(0, self._restore_window)

  def _restore_window(self):
    self.root.deiconify()
    self.root.lift()
    self.root.focus_force()

  def _tray_disarm(self, icon=None, item=None):
    self._stop_tray_icon()
    self.root.after(0, self._prompt_disarm_from_tray)

  def _prompt_disarm_from_tray(self):
    if self.verify_disarm_password():
      self.auto_arm_var.set(False)
      self.stop_monitoring()
      self._restore_window()
    else:
      self.hide_to_tray()

  def _tray_exit(self, icon=None, item=None):
    self._stop_tray_icon()
    self.root.after(0, self._prompt_exit_from_tray)

  def _prompt_exit_from_tray(self):
    if self.monitoring:
      if not self.verify_disarm_password():
        self.hide_to_tray()
        return
    self.app_running = False
    self.root.destroy()

  def on_close_window(self):
    if self.monitoring or self.auto_arm_var.get():
      self.hide_to_tray()
    else:
      self.app_running = False
      self._stop_tray_icon()
      self.root.destroy()

  # --- USB & HARDWARE KEY VERIFICATION / SETUP ---
  def get_usb_drives(self):
    drives = []
    for part in psutil.disk_partitions(all=False):
      if OS_TYPE == "Windows":
        if "removable" in part.opts.lower():
          dev = part.device.rstrip("\\")
          hw_id = self.get_drive_hardware_serial(dev, part.mountpoint)
          drives.append((dev, part.mountpoint, hw_id))
      elif OS_TYPE == "Linux":
        if part.mountpoint.startswith(("/media", "/run/media", "/mnt")):
          hw_id = self.get_drive_hardware_serial(part.device, part.mountpoint)
          drives.append((part.device, part.mountpoint, hw_id))
    return drives

  def refresh_drives(self):
    if self.monitoring:
      return
    self.drive_listbox.delete(0, tk.END)
    self.drives = self.get_usb_drives()
    if not self.drives:
      self.drive_listbox.insert(tk.END, "No removable USB drives detected.")
    else:
      for dev, mount, hw_id in self.drives:
        self.drive_listbox.insert(
            tk.END, f"{dev}  -->  {mount}   [HW Serial: {hw_id}]"
        )

  def provision_usb_key(self):
    selection = self.drive_listbox.curselection()
    if not selection or not self.drives:
      messagebox.showwarning(
          "Select a Drive",
          "Please select a USB drive from the list to set up as a security key.",
      )
      return

    selected_device, selected_mount, hw_id = self.drives[selection[0]]
    if "UNKNOWN" in hw_id or "UNSUPPORTED" in hw_id:
      messagebox.showerror(
          "Hardware ID Error",
          f"Could not read a valid hardware serial number from {selected_device}.",
      )
      return

    key_path = os.path.join(selected_mount, KEY_FILENAME)

    confirm = messagebox.askyesno(
        "Bind Hardware Security Key",
        f"Configure {selected_device} (Serial: {hw_id}) as your Secure USB Key?\n\n"
        f"This writes a hidden SHA-256 cryptographic signature bound to this "
        f"specific drive's hardware serial number and this PC.",
    )
    if not confirm:
      return

    try:
      if OS_TYPE == "Windows" and os.path.exists(key_path):
        ctypes.windll.kernel32.SetFileAttributesW(
            key_path, FILE_ATTRIBUTE_NORMAL
        )

      hw_token = self.generate_hardware_token(selected_device, selected_mount)

      with open(key_path, "w", encoding="utf-8") as f:
        f.write(hw_token)

      if OS_TYPE == "Windows":
        ctypes.windll.kernel32.SetFileAttributesW(
            key_path, FILE_ATTRIBUTE_HIDDEN
        )

      self.status_var.set(
          f"Status: Hardware-bound SHA-256 key installed on {selected_device} [{hw_id}]!"
      )
      messagebox.showinfo(
          "Hardware Key Bound",
          f"{selected_device} [Serial: {hw_id}] is now cryptographically bound!\n\n"
          f"You can now click 'Verify & Arm Lock'.",
      )
    except Exception as e:
      messagebox.showerror(
          "Setup Failed",
          f"Could not write key file to {selected_device}.\nError: {e}",
      )

  def verify_drive_key(self, device: str, mountpoint: str) -> bool:
    key_path = os.path.join(mountpoint, KEY_FILENAME)
    if not os.path.isfile(key_path):
      return False
    try:
      with open(key_path, "r", encoding="utf-8") as f:
        stored_token = f.read().strip()

      expected_hw_token = self.generate_hardware_token(device, mountpoint)
      return hmac.compare_digest(stored_token, expected_hw_token)
    except Exception:
      return False

  # --- ARMING & DISARMING LOGIC ---
  def _arm_specific_drive(self, device: str, hw_id: str):
    self.monitored_device = device
    self.monitoring = True

    self.monitor_btn.config(text="Disarm Lock")
    self.refresh_btn.config(state=tk.DISABLED)
    self.setup_btn.config(state=tk.DISABLED)
    self.pw_btn.config(state=tk.DISABLED)
    self.drive_listbox.config(state=tk.DISABLED)
    self.status_var.set(
        f"Status: ARMED [{hw_id}]! Removing {self.monitored_device} will lock Windows."
    )

    self.hide_to_tray()

  def _check_existing_drives_for_auto_arm(self):
    if self.monitoring or not self.auto_arm_var.get():
      return

    self.refresh_drives()
    for dev, mount, hw_id in self.drives:
      if self.verify_drive_key(dev, mount):
        self._arm_specific_drive(dev, hw_id)
        break

  def toggle_monitoring(self):
    if not self.monitoring:
      selection = self.drive_listbox.curselection()
      if not selection or not self.drives:
        messagebox.showwarning(
            "Select a Drive", "Please select a valid USB drive from the list."
        )
        return

      selected_device, selected_mount, hw_id = self.drives[selection[0]]

      if not self.verify_drive_key(selected_device, selected_mount):
        messagebox.showerror(
            "Invalid or Cloned Security Key",
            "This Drive cannot be used as a secure key.\n\n"
            "(Either the key file is missing, or it was copied from a different USB drive).",
        )
        self.status_var.set(
            f"Status: Hardware verification failed for {selected_device} [{hw_id}]"
        )
        return

      self.auto_arm_var.set(True)
      self._arm_specific_drive(selected_device, hw_id)
    else:
      if self.verify_disarm_password():
        self.auto_arm_var.set(False)
        self.stop_monitoring()

  def stop_monitoring(self):
    self.monitoring = False
    self.monitored_device = None
    self._stop_tray_icon()
    self.monitor_btn.config(text="Verify & Arm Lock")
    self.refresh_btn.config(state=tk.NORMAL)
    self.setup_btn.config(state=tk.NORMAL)
    self.pw_btn.config(state=tk.NORMAL)
    self.drive_listbox.config(state=tk.NORMAL)
    self.status_var.set("Status: Idle (Disarmed)")
    self.refresh_drives()

  def lock_system(self):
    if OS_TYPE == "Windows":
      ctypes.windll.user32.LockWorkStation()
    elif OS_TYPE == "Linux":
      subprocess.run(["loginctl", "lock-session"], check=False)

  def trigger_lock_action(self, dev_name):
    self.lock_system()
    self.root.after(0, self._post_lock_cleanup, dev_name)

  def _post_lock_cleanup(self, dev_name):
    self.stop_monitoring()
    self._restore_window()
    self.status_var.set(
        f"Status: Locked ({dev_name} removed). Plug key back in to Auto-Arm!"
    )

  # --- ZERO-POLLING OS HARDWARE EVENT BUS (ARRIVAL + REMOVAL) ---
  def _start_os_event_bus(self):
    if OS_TYPE == "Windows":
      self._event_bus_windows()
    elif OS_TYPE == "Linux":
      self._event_bus_linux()

  def _event_bus_windows(self):
    pythoncom.CoInitialize()
    try:
      c = wmi.WMI()
      watcher = c.Win32_VolumeChangeEvent.watch_for()
      while self.app_running:
        try:
          event = watcher(timeout_ms=500)
          if not event:
            continue

          event_type = getattr(event, "EventType", None)
          drive_name = getattr(event, "DriveName", "")

          if event_type == 3 and self.monitoring and self.monitored_device:
            if drive_name.upper() == self.monitored_device.upper():
              self.trigger_lock_action(self.monitored_device)

          elif event_type == 2 and not self.monitoring:
            time.sleep(0.4)
            self.root.after(0, self._check_existing_drives_for_auto_arm)

        except wmi.x_wmi_timed_out:
          continue
        except Exception:
          continue
    finally:
      pythoncom.CoUninitialize()

  def _event_bus_linux(self):
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")

    for device in iter(monitor.poll, None):
      if not self.app_running:
        break
      if (
          device.action == "remove"
          and self.monitoring
          and device.device_node == self.monitored_device
      ):
        self.trigger_lock_action(self.monitored_device)
      elif device.action == "add" and not self.monitoring:
        time.sleep(0.6)
        self.root.after(0, self._check_existing_drives_for_auto_arm)


if __name__ == "__main__":
  # Prevent multiple instances on Windows using a kernel Named Mutex
  mutex = None
  if OS_TYPE == "Windows":
    mutex = ctypes.windll.kernel32.CreateMutexW(
        None, False, "Global\\USBKeyLock_SingleInstance_Mutex"
    )
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
      ctypes.windll.user32.MessageBoxW(
          0,
          "USBKeyLock is already running! Check your Windows System Tray (by the clock).",
          "USBKeyLock Already Running",
          0x40,
      )
      sys.exit(0)

  root = tk.Tk()
  app = USBMonitorApp(root)
  root.mainloop() 
