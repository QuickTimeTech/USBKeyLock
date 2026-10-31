import ctypes
from datetime import datetime
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
from tkinter import messagebox
import customtkinter as ctk
from PIL import Image, ImageDraw, ImageTk
import psutil
import pystray

OS_TYPE = platform.system()
APP_NAME = "USBKeyLock"
APP_VERSION = "2.0.0"

if OS_TYPE == "Windows":
  import pythoncom
  import pywintypes
  import wmi
  import winreg
  import winsound
elif OS_TYPE == "Linux":
  import pyudev

# Set CustomTkinter appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


# --- BUNDLED RESOURCE, ICON GENERATOR & OS APPDATA PATHS ---
def get_resource_path(relative_path: str) -> str:
  """Gets the path to bundled resources (like app_icon.ico) inside PyInstaller .exe or source."""
  base_path = getattr(
      sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))
  )
  return os.path.join(base_path, relative_path)


def get_appdata_dir() -> str:
  """Returns a user-writable OS application data directory."""
  if OS_TYPE == "Windows":
    base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    path = os.path.join(base, APP_NAME)
  else:
    path = os.path.join(os.path.expanduser("~"), ".config", APP_NAME.lower())
  os.makedirs(path, exist_ok=True)
  return path


APPDATA_DIR = get_appdata_dir()
CONFIG_FILE = os.path.join(APPDATA_DIR, "security_config.json")
AUDIT_LOG_FILE = os.path.join(APPDATA_DIR, "security_audit.log")


def ensure_icon_file() -> str:
  """Locates app_icon.ico or dynamically creates it on disk so it is always available."""
  bundled_ico = get_resource_path("app_icon.ico")
  if os.path.isfile(bundled_ico):
    return bundled_ico

  local_ico = os.path.join(
      os.path.dirname(os.path.abspath(__file__)), "app_icon.ico"
  )
  if os.path.isfile(local_ico):
    return local_ico

  fallback_ico = os.path.join(APPDATA_DIR, "app_icon.ico")
  target_ico = local_ico if not getattr(sys, "frozen", False) else fallback_ico

  if not os.path.isfile(target_ico):
    try:
      img = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
      d = ImageDraw.Draw(img)
      d.rounded_rectangle(
          (16, 16, 240, 240), radius=56, fill="#0F2537", outline="#107C41", width=12
      )
      d.arc((86, 56, 170, 140), start=180, end=0, fill="#FFFFFF", width=18)
      d.rounded_rectangle(
          (68, 112, 188, 204), radius=18, fill="#107C41", outline="#FFFFFF", width=8
      )
      d.ellipse((116, 142, 140, 166), fill="#FFFFFF")
      d.polygon([(122, 160), (134, 160), (138, 186), (118, 186)], fill="#FFFFFF")
      img.save(
          target_ico,
          format="ICO",
          sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)],
      )
    except Exception:
      pass
  return target_ico


KEY_FILENAME = ".usb_key.txt"
PBKDF2_ITERATIONS = 100000
FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_NORMAL = 0x80

ACTION_MODES = [
    "Lock Screen",
    "Lock + Mute Audio",
    "Hibernate / Sleep PC",
    "Force Shutdown (Dead Man's Switch)",
]

GRACE_PERIODS = {
    "Instant (0s)": 0,
    "3 Seconds": 3,
    "5 Seconds": 5,
    "10 Seconds": 10,
}


class AuditLogger:
  """Manages timestamped security events saved to disk and viewable in the UI."""

  @staticmethod
  def log(event_type: str, message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{event_type.upper()}] {message}\n"
    try:
      with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)
    except Exception:
      pass

  @staticmethod
  def read_logs(max_lines: int = 250) -> str:
    if not os.path.isfile(AUDIT_LOG_FILE):
      return "No security events recorded yet."
    try:
      with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
      return "".join(lines[-max_lines:])
    except Exception:
      return "Could not read audit log file."

  @staticmethod
  def clear_logs():
    try:
      with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
        f.write("")
      AuditLogger.log(
          "INFO", "Security audit log cleared by authenticated user."
      )
    except Exception:
      pass


class SecurityConfig:
  """Manages per-installation cryptographic salts, settings, and authorized keys."""

  def __init__(self):
    self.hw_salt = ""
    self.pw_salt = ""
    self.password_hash = ""
    self.is_default_pw = True
    self.auto_arm = True
    self.action_mode = ACTION_MODES[0]
    self.grace_label = "Instant (0s)"
    # Dict mapping hw_serial -> {"label": str, "added": str}
    self.authorized_keys = {}
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
          self.auto_arm = data.get("auto_arm", True)
          self.action_mode = data.get("action_mode", ACTION_MODES[0])
          self.grace_label = data.get("grace_label", "Instant (0s)")
          self.authorized_keys = data.get("authorized_keys", {})
          return
      except Exception:
        pass

    # First run on this PC: generate unique cryptographic salts
    self.hw_salt = secrets.token_hex(32)
    self.pw_salt = secrets.token_hex(32)
    self.password_hash = self.hash_password("admin")
    self.is_default_pw = True
    self.save()
    AuditLogger.log(
        "INIT", "First launch: generated unique 256-bit machine salts."
    )

  def save(self):
    data = {
        "hw_salt": self.hw_salt,
        "pw_salt": self.pw_salt,
        "password_hash": self.password_hash,
        "is_default_pw": self.is_default_pw,
        "auto_arm": self.auto_arm,
        "action_mode": self.action_mode,
        "grace_label": self.grace_label,
        "authorized_keys": self.authorized_keys,
    }
    try:
      with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    except Exception:
      pass


class USBMonitorApp:

  def __init__(self, root: ctk.CTk, start_minimized: bool = False):
    self.root = root
    self.root.title(f"{APP_NAME} v{APP_VERSION} — Hardware Security Suite")
    self.root.geometry("760x540")
    self.root.resizable(False, False)

    # Apply custom Windows Taskbar AppUserModelID and window icon
    self._tk_icon = None
    self._apply_window_icon()
    # CustomTkinter overwrites the icon at ~200ms; re-apply at 250ms and 600ms to beat it!
    self.root.after(250, self._apply_window_icon)
    self.root.after(600, self._apply_window_icon)

    self.config = SecurityConfig()
    self.monitoring = False
    self.monitored_device = None
    self.monitored_hw_id = None
    self.app_running = True
    self.tray_icon = None

    # Grace period countdown state
    self.grace_active = False
    self.grace_window = None
    self.grace_remaining = 0

    # Selection tracking
    self.drives = []
    self.auth_serials_list = []

    self.root.protocol("WM_DELETE_WINDOW", self.on_close_window)

    self._build_ui()
    self.refresh_drives()
    self.refresh_authorized_keys_ui()
    self.refresh_audit_log_ui()

    threading.Thread(target=self._start_os_event_bus, daemon=True).start()
    self.root.after(600, self._check_existing_drives_for_auto_arm)

    if start_minimized:
      self.root.after(200, self.hide_to_tray)

  def _apply_window_icon(self):
    """Forces CustomTkinter title bar and Windows Taskbar to use app_icon.ico."""
    icon_path = ensure_icon_file()
    if os.path.isfile(icon_path):
      try:
        self.root.iconbitmap(default=icon_path)
        self.root.wm_iconbitmap(icon_path)
        pil_img = Image.open(icon_path)
        self._tk_icon = ImageTk.PhotoImage(pil_img)
        self.root.wm_iconphoto(True, self._tk_icon)
      except Exception:
        pass

  # --- WINDOWS STARTUP REGISTRY INTEGRATION ---
  def _get_startup_cmd(self) -> str:
    if getattr(sys, "frozen", False):
      return f'"{sys.executable}" --minimized'
    else:
      script_path = os.path.abspath(__file__)
      return f'"{sys.executable}" "{script_path}" --minimized'

  def is_startup_enabled(self) -> bool:
    if OS_TYPE != "Windows":
      return False
    try:
      key = winreg.OpenKey(
          winreg.HKEY_CURRENT_USER,
          r"Software\Microsoft\Windows\CurrentVersion\Run",
          0,
          winreg.KEY_READ,
      )
      val, _ = winreg.QueryValueEx(key, APP_NAME)
      winreg.CloseKey(key)
      return bool(val)
    except Exception:
      return False

  def set_startup_registry(self, enable: bool):
    if OS_TYPE != "Windows":
      messagebox.showinfo(
          "Windows Feature",
          "Registry startup integration is only supported on Windows.",
      )
      self.startup_switch_var.set(False)
      return
    try:
      key = winreg.OpenKey(
          winreg.HKEY_CURRENT_USER,
          r"Software\Microsoft\Windows\CurrentVersion\Run",
          0,
          winreg.KEY_SET_VALUE,
      )
      if enable:
        winreg.SetValueEx(
            key, APP_NAME, 0, winreg.REG_SZ, self._get_startup_cmd()
        )
        AuditLogger.log("CONFIG", "Enabled 'Launch at Windows Startup'.")
      else:
        try:
          winreg.DeleteValue(key, APP_NAME)
        except FileNotFoundError:
          pass
        AuditLogger.log("CONFIG", "Disabled 'Launch at Windows Startup'.")
      winreg.CloseKey(key)
      self.refresh_audit_log_ui()
    except Exception as e:
      messagebox.showerror("Registry Error", f"Failed to update startup: {e}")

  # --- MODERN DARK-MODE UI (CUSTOMTKINTER) ---
  def _build_ui(self):
    # Top Header Bar
    header = ctk.CTkFrame(self.root, height=60, corner_radius=0)
    header.pack(fill="x", padx=0, pady=0)

    title_lbl = ctk.CTkLabel(
        header,
        text=f"🛡️ {APP_NAME} Pro",
        font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
    )
    title_lbl.pack(side="left", padx=20, pady=12)

    self.badge_lbl = ctk.CTkLabel(
        header,
        text="● STANDBY (IDLE)",
        font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
        fg_color="#1F538D",
        corner_radius=12,
        padx=14,
        pady=4,
    )
    self.badge_lbl.pack(side="right", padx=20, pady=12)

    # Tabview
    self.tabview = ctk.CTkTabview(self.root, width=720, height=400)
    self.tabview.pack(fill="both", expand=True, padx=20, pady=(10, 5))

    self.tab_main = self.tabview.add("USB Drives & Control")
    self.tab_keys = self.tabview.add("Authorized Keys")
    self.tab_logs = self.tabview.add("Security Audit Log")

    self._build_main_tab()
    self._build_keys_tab()
    self._build_logs_tab()

    # Bottom Status Bar
    default_msg = (
        "Ready | Default disarm password is 'admin' (Click 'Set Password' to secure)"
        if self.config.is_default_pw
        else "Ready | Custom PBKDF2 password active"
    )
    self.status_var = tk.StringVar(value=default_msg)
    status_bar = ctk.CTkLabel(
        self.root,
        textvariable=self.status_var,
        font=ctk.CTkFont(family="Segoe UI", size=12),
        text_color="#A0A0A0",
        anchor="w",
    )
    status_bar.pack(fill="x", padx=24, pady=(0, 10))

  def _build_main_tab(self):
    # Left Column: Connected Drives List
    left_frame = ctk.CTkFrame(self.tab_main)
    left_frame.pack(side="left", fill="both", expand=True, padx=(5, 10), pady=5)

    ctk.CTkLabel(
        left_frame,
        text="Connected Removable USB Drives:",
        font=ctk.CTkFont(size=13, weight="bold"),
    ).pack(anchor="w", padx=12, pady=(10, 4))

    self.drive_listbox = tk.Listbox(
        left_frame,
        font=("Consolas", 10),
        bg="#1E1E1E",
        fg="#E0E0E0",
        selectbackground="#1F538D",
        selectforeground="#FFFFFF",
        highlightthickness=0,
        bd=0,
        height=9,
        selectmode=tk.SINGLE,
    )
    self.drive_listbox.pack(fill="both", expand=True, padx=12, pady=6)

    drive_btn_row = ctk.CTkFrame(left_frame, fg_color="transparent")
    drive_btn_row.pack(fill="x", padx=12, pady=(4, 10))

    self.refresh_btn = ctk.CTkButton(
        drive_btn_row,
        text="🔄 Refresh",
        width=100,
        command=self.refresh_drives,
    )
    self.refresh_btn.pack(side="left", padx=(0, 8))

    self.setup_btn = ctk.CTkButton(
        drive_btn_row,
        text="🔑 Setup Hardware Key",
        fg_color="#2B7A3E",
        hover_color="#1E562B",
        command=self.provision_usb_key,
    )
    self.setup_btn.pack(side="left", fill="x", expand=True)

    # Right Column: Security Settings & Arm Controls
    right_frame = ctk.CTkFrame(self.tab_main, width=290)
    right_frame.pack(side="right", fill="y", padx=(0, 5), pady=5)
    right_frame.pack_propagate(False)

    ctk.CTkLabel(
        right_frame,
        text="Protection Settings",
        font=ctk.CTkFont(size=13, weight="bold"),
    ).pack(anchor="w", padx=14, pady=(10, 6))

    # Action Mode Selector
    ctk.CTkLabel(
        right_frame, text="Unplug Action Mode:", font=ctk.CTkFont(size=12)
    ).pack(anchor="w", padx=14, pady=(2, 0))
    self.action_mode_var = ctk.StringVar(value=self.config.action_mode)
    self.action_menu = ctk.CTkOptionMenu(
        right_frame,
        values=ACTION_MODES,
        variable=self.action_mode_var,
        command=self._on_settings_change,
        width=260,
    )
    self.action_menu.pack(padx=14, pady=(2, 8))

    # Grace Period Selector
    ctk.CTkLabel(
        right_frame,
        text="Grace Period (Bump Protection):",
        font=ctk.CTkFont(size=12),
    ).pack(anchor="w", padx=14, pady=(2, 0))
    self.grace_var = ctk.StringVar(value=self.config.grace_label)
    self.grace_menu = ctk.CTkOptionMenu(
        right_frame,
        values=list(GRACE_PERIODS.keys()),
        variable=self.grace_var,
        command=self._on_settings_change,
        width=260,
    )
    self.grace_menu.pack(padx=14, pady=(2, 10))

    # Switches
    self.auto_arm_var = ctk.BooleanVar(value=self.config.auto_arm)
    self.auto_arm_switch = ctk.CTkSwitch(
        right_frame,
        text="Auto-Arm on USB Plug-In",
        variable=self.auto_arm_var,
        command=self._on_settings_change,
    )
    self.auto_arm_switch.pack(anchor="w", padx=14, pady=4)

    self.startup_switch_var = ctk.BooleanVar(value=self.is_startup_enabled())
    self.startup_switch = ctk.CTkSwitch(
        right_frame,
        text="Start with Windows (Tray)",
        variable=self.startup_switch_var,
        command=lambda: self.set_startup_registry(
            self.startup_switch_var.get()
        ),
    )
    self.startup_switch.pack(anchor="w", padx=14, pady=4)

    # Primary Action Buttons
    self.monitor_btn = ctk.CTkButton(
        right_frame,
        text="🛡️ Verify & Arm Lock",
        font=ctk.CTkFont(size=13, weight="bold"),
        height=36,
        command=self.toggle_monitoring,
    )
    self.monitor_btn.pack(fill="x", padx=14, pady=(12, 6))

    sub_btn_row = ctk.CTkFrame(right_frame, fg_color="transparent")
    sub_btn_row.pack(fill="x", padx=14, pady=2)

    self.pw_btn = ctk.CTkButton(
        sub_btn_row,
        text="Set Password",
        width=124,
        fg_color="#3B3B3B",
        hover_color="#505050",
        command=self.change_password_dialog,
    )
    self.pw_btn.pack(side="left", padx=(0, 6))

    self.hide_btn = ctk.CTkButton(
        sub_btn_row,
        text="Hide to Tray",
        width=124,
        fg_color="#3B3B3B",
        hover_color="#505050",
        command=self.hide_to_tray,
    )
    self.hide_btn.pack(side="right")

  def _build_keys_tab(self):
    ctk.CTkLabel(
        self.tab_keys,
        text="Authorized Hardware USB Keys (Whitelisted Serials):",
        font=ctk.CTkFont(size=13, weight="bold"),
    ).pack(anchor="w", padx=12, pady=(8, 4))

    self.auth_keys_listbox = tk.Listbox(
        self.tab_keys,
        font=("Consolas", 10),
        bg="#1E1E1E",
        fg="#E0E0E0",
        selectbackground="#8B2635",
        selectforeground="#FFFFFF",
        highlightthickness=0,
        bd=0,
        height=11,
        selectmode=tk.SINGLE,
    )
    self.auth_keys_listbox.pack(fill="both", expand=True, padx=12, pady=6)

    btn_row = ctk.CTkFrame(self.tab_keys, fg_color="transparent")
    btn_row.pack(fill="x", padx=12, pady=8)

    ctk.CTkLabel(
        btn_row,
        text="Lost a USB stick? Select it above and click Revoke so it can never unlock or arm this PC.",
        font=ctk.CTkFont(size=11),
        text_color="#A0A0A0",
    ).pack(side="left")

    self.revoke_btn = ctk.CTkButton(
        btn_row,
        text="🚫 Revoke Selected Key",
        fg_color="#A82020",
        hover_color="#7A1515",
        command=self.revoke_selected_key,
    )
    self.revoke_btn.pack(side="right")

  def _build_logs_tab(self):
    top_row = ctk.CTkFrame(self.tab_logs, fg_color="transparent")
    top_row.pack(fill="x", padx=10, pady=(6, 4))

    ctk.CTkLabel(
        top_row,
        text="Tamper & Activity Audit Log:",
        font=ctk.CTkFont(size=13, weight="bold"),
    ).pack(side="left")

    ctk.CTkButton(
        top_row,
        text="Clear Log",
        width=90,
        height=26,
        fg_color="#3B3B3B",
        hover_color="#505050",
        command=self.clear_audit_log_protected,
    ).pack(side="right", padx=(6, 0))

    ctk.CTkButton(
        top_row,
        text="Refresh",
        width=80,
        height=26,
        command=self.refresh_audit_log_ui,
    ).pack(side="right")

    self.log_textbox = ctk.CTkTextbox(
        self.tab_logs,
        font=ctk.CTkFont(family="Consolas", size=11),
        wrap="none",
    )
    self.log_textbox.pack(fill="both", expand=True, padx=10, pady=6)

  def _on_settings_change(self, _=None):
    self.config.action_mode = self.action_mode_var.get()
    self.config.grace_label = self.grace_var.get()
    self.config.auto_arm = self.auto_arm_var.get()
    self.config.save()

  # --- HARDWARE SERIAL & VOLUME NAME ---
  def get_drive_hardware_info(self, device: str, mountpoint: str):
    """Returns (hw_serial, volume_label) for the USB partition."""
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
        label = vol_name_buf.value.strip() or "USB Drive"
        return f"{serial_num.value:08X}", label
      return "UNKNOWN_WIN_SERIAL", "USB Drive"

    elif OS_TYPE == "Linux":
      try:
        out = subprocess.check_output(
            ["lsblk", "-no", "UUID,LABEL", device], text=True
        ).strip()
        parts = out.split(maxsplit=1)
        uuid = parts[0] if parts else "UNKNOWN_LINUX_UUID"
        label = parts[1] if len(parts) > 1 else "USB Drive"
        return uuid, label
      except Exception:
        return "UNKNOWN_LINUX_UUID", "USB Drive"

    return "UNSUPPORTED_OS_SERIAL", "USB Drive"

  def generate_hardware_token(self, hw_serial: str) -> str:
    payload = f"{hw_serial}::{self.config.hw_salt}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

  # --- PASSWORD VERIFICATION ---
  def prompt_password(self, title: str, prompt_text: str):
    dialog = ctk.CTkInputDialog(text=prompt_text, title=title)
    if hasattr(dialog, "_entry"):
      dialog._entry.configure(show="*")
    return dialog.get_input()

  def verify_disarm_password(self) -> bool:
    self._restore_window()
    entered_pw = self.prompt_password(
        "Authentication Required", "Enter your disarm password:"
    )
    if entered_pw is None:
      return False

    entered_hash = self.config.hash_password(entered_pw)
    if hmac.compare_digest(entered_hash, self.config.password_hash):
      return True
    else:
      AuditLogger.log("ALERT", "Failed password authentication attempt!")
      self.refresh_audit_log_ui()
      messagebox.showerror("Access Denied", "Incorrect password!")
      return False

  def change_password_dialog(self):
    if not self.verify_disarm_password():
      return

    new_pw = self.prompt_password(
        "Set New Password", "Enter your new disarm password:"
    )
    if not new_pw:
      return

    confirm_pw = self.prompt_password(
        "Confirm Password", "Re-enter your new disarm password:"
    )
    if new_pw != confirm_pw:
      messagebox.showerror("Mismatch", "Passwords did not match.")
      return

    self.config.password_hash = self.config.hash_password(new_pw)
    self.config.is_default_pw = False
    self.config.save()

    AuditLogger.log("SECURITY", "Disarm password updated by user.")
    self.refresh_audit_log_ui()
    messagebox.showinfo(
        "Password Updated",
        "Your new disarm password has been salted, hashed, and saved!",
    )
    self.status_var.set("Custom PBKDF2 password saved and active.")

  # --- AUTHORIZED KEYS & REVOCATION ---
  def refresh_authorized_keys_ui(self):
    self.auth_keys_listbox.delete(0, tk.END)
    self.auth_serials_list = list(self.config.authorized_keys.keys())
    if not self.auth_serials_list:
      self.auth_keys_listbox.insert(
          tk.END, "No USB keys have been provisioned on this PC yet."
      )
    else:
      for serial in self.auth_serials_list:
        info = self.config.authorized_keys[serial]
        label = info.get("label", "USB Key")
        added = info.get("added", "Unknown Date")
        self.auth_keys_listbox.insert(
            tk.END,
            f"HW Serial: {serial}  |  Name: {label:<16}  |  Provisioned: {added}",
        )

  def revoke_selected_key(self):
    selection = self.auth_keys_listbox.curselection()
    if not selection or not self.auth_serials_list:
      messagebox.showwarning(
          "Select a Key", "Please select an authorized key to revoke."
      )
      return

    serial_to_revoke = self.auth_serials_list[selection[0]]
    key_info = self.config.authorized_keys.get(serial_to_revoke, {})
    label = key_info.get("label", "USB Key")

    if not self.verify_disarm_password():
      return

    confirm = messagebox.askyesno(
        "Confirm Key Revocation",
        f"Permanently revoke '{label}' [Serial: {serial_to_revoke}]?\n\n"
        f"This USB stick will immediately lose access until re-provisioned.",
    )
    if not confirm:
      return

    del self.config.authorized_keys[serial_to_revoke]
    self.config.save()
    AuditLogger.log(
        "REVOKE",
        f"Revoked hardware key '{label}' [Serial: {serial_to_revoke}].",
    )
    self.refresh_authorized_keys_ui()
    self.refresh_audit_log_ui()
    self.refresh_drives()

    if self.monitoring and self.monitored_hw_id == serial_to_revoke:
      self.stop_monitoring()

  def clear_audit_log_protected(self):
    if self.verify_disarm_password():
      AuditLogger.clear_logs()
      self.refresh_audit_log_ui()

  def refresh_audit_log_ui(self):
    self.log_textbox.configure(state="normal")
    self.log_textbox.delete("1.0", "end")
    self.log_textbox.insert("end", AuditLogger.read_logs())
    self.log_textbox.see("end")
    self.log_textbox.configure(state="disabled")

  # --- SYSTEM TRAY MANAGEMENT ---
  def _create_tray_image(self, armed: bool):
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    bg_color = "#107C41" if armed else "#1F538D"
    draw.ellipse((4, 4, 60, 60), fill=bg_color, outline="#FFFFFF", width=3)
    draw.arc((22, 14, 42, 34), start=180, end=0, fill="white", width=4)
    draw.rectangle((18, 28, 46, 48), fill="white")
    return image

  def hide_to_tray(self):
    self.root.withdraw()
    self._stop_tray_icon()

    image = self._create_tray_image(armed=self.monitoring)
    tooltip = (
        f"USBKeyLock ARMED ({self.monitored_device})"
        if self.monitoring
        else "USBKeyLock Standby (Waiting for Key)"
    )

    menu_items = [
        pystray.MenuItem("Show Dashboard", self._tray_show_window, default=True)
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
    self.root.after(50, self._apply_window_icon)

  def _tray_disarm(self, icon=None, item=None):
    self._stop_tray_icon()
    self.root.after(0, self._prompt_disarm_from_tray)

  def _prompt_disarm_from_tray(self):
    if self.verify_disarm_password():
      self.auto_arm_var.set(False)
      self._on_settings_change()
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

  # --- USB DETECTION & KEY SETUP ---
  def get_usb_drives(self):
    drives = []
    for part in psutil.disk_partitions(all=False):
      if OS_TYPE == "Windows":
        if "removable" in part.opts.lower():
          dev = part.device.rstrip("\\")
          hw_id, label = self.get_drive_hardware_info(dev, part.mountpoint)
          drives.append((dev, part.mountpoint, hw_id, label))
      elif OS_TYPE == "Linux":
        if part.mountpoint.startswith(("/media", "/run/media", "/mnt")):
          hw_id, label = self.get_drive_hardware_info(
              part.device, part.mountpoint
          )
          drives.append((part.device, part.mountpoint, hw_id, label))
    return drives

  def refresh_drives(self):
    if self.monitoring:
      return
    self.drive_listbox.delete(0, tk.END)
    self.drives = self.get_usb_drives()
    if not self.drives:
      self.drive_listbox.insert(tk.END, " No removable USB drives detected.")
    else:
      for dev, mount, hw_id, label in self.drives:
        status_tag = (
            "✓ AUTH" if hw_id in self.config.authorized_keys else "UNREGISTERED"
        )
        self.drive_listbox.insert(
            tk.END, f" {dev} [{label}]  |  SN: {hw_id}  ({status_tag})"
        )

  def provision_usb_key(self):
    selection = self.drive_listbox.curselection()
    if not selection or not self.drives:
      messagebox.showwarning(
          "Select a Drive",
          "Please select a USB drive from the list to configure.",
      )
      return

    selected_device, selected_mount, hw_id, label = self.drives[selection[0]]
    if "UNKNOWN" in hw_id or "UNSUPPORTED" in hw_id:
      messagebox.showerror(
          "Hardware ID Error",
          f"Could not read a valid hardware serial number from {selected_device}.",
      )
      return

    if not self.config.is_default_pw:
      if not self.verify_disarm_password():
        return

    key_path = os.path.join(selected_mount, KEY_FILENAME)

    confirm = messagebox.askyesno(
        "Bind Hardware Security Key",
        f"Configure {selected_device} ({label} | Serial: {hw_id}) as an Authorized USB Key?\n\n"
        f"This writes a hidden SHA-256 cryptographic signature bound to this "
        f"drive's hardware serial number and whitelists it on this PC.",
    )
    if not confirm:
      return

    try:
      if OS_TYPE == "Windows" and os.path.exists(key_path):
        ctypes.windll.kernel32.SetFileAttributesW(
            key_path, FILE_ATTRIBUTE_NORMAL
        )

      hw_token = self.generate_hardware_token(hw_id)

      with open(key_path, "w", encoding="utf-8") as f:
        f.write(hw_token)

      if OS_TYPE == "Windows":
        ctypes.windll.kernel32.SetFileAttributesW(
            key_path, FILE_ATTRIBUTE_HIDDEN
        )

      self.config.authorized_keys[hw_id] = {
          "label": label,
          "added": datetime.now().strftime("%Y-%m-%d %H:%M"),
      }
      self.config.save()

      AuditLogger.log(
          "PROVISION",
          f"Provisioned & whitelisted USB key '{label}' ({selected_device} | SN: {hw_id}).",
      )
      self.refresh_authorized_keys_ui()
      self.refresh_audit_log_ui()
      self.refresh_drives()

      self.status_var.set(
          f"Hardware-bound SHA-256 key installed on {selected_device} [{hw_id}]!"
      )
      messagebox.showinfo(
          "Hardware Key Bound",
          f"{selected_device} ({label}) is now cryptographically bound and whitelisted!\n\n"
          f"Click 'Verify & Arm Lock' to arm.",
      )
    except Exception as e:
      messagebox.showerror(
          "Setup Failed",
          f"Could not write key file to {selected_device}.\nError: {e}",
      )

  def verify_drive_key(self, device: str, mountpoint: str, hw_id: str) -> bool:
    """Checks both the whitelist AND the physical hidden SHA-256 token file."""
    if hw_id not in self.config.authorized_keys:
      return False

    key_path = os.path.join(mountpoint, KEY_FILENAME)
    if not os.path.isfile(key_path):
      return False
    try:
      with open(key_path, "r", encoding="utf-8") as f:
        stored_token = f.read().strip()

      expected_hw_token = self.generate_hardware_token(hw_id)
      return hmac.compare_digest(stored_token, expected_hw_token)
    except Exception:
      return False

  # --- ARMING, GRACE PERIOD COUNTDOWN & ACTION MODES ---
  def _arm_specific_drive(self, device: str, hw_id: str, label: str):
    self.monitored_device = device
    self.monitored_hw_id = hw_id
    self.monitoring = True

    self.badge_lbl.configure(
        text=f"● ARMED ({device})", fg_color="#107C41"
    )
    self.monitor_btn.configure(
        text="🔓 Disarm Lock (Password Required)",
        fg_color="#A82020",
        hover_color="#7A1515",
    )
    self.refresh_btn.configure(state="disabled")
    self.setup_btn.configure(state="disabled")
    self.pw_btn.configure(state="disabled")
    self.drive_listbox.config(state=tk.DISABLED)

    self.status_var.set(
        f"ARMED: {device} [{label} | SN: {hw_id}] — Mode: {self.config.action_mode}"
    )
    AuditLogger.log(
        "ARMED",
        f"Protection armed on {device} [SN: {hw_id}] (Action: {self.config.action_mode}).",
    )
    self.refresh_audit_log_ui()
    self.hide_to_tray()

  def _check_existing_drives_for_auto_arm(self):
    if self.grace_active and self.monitored_hw_id:
      current_drives = self.get_usb_drives()
      for dev, mount, hw_id, label in current_drives:
        if hw_id == self.monitored_hw_id and self.verify_drive_key(
            dev, mount, hw_id
        ):
          self._cancel_grace_countdown(dev)
          return

    if self.monitoring or not self.auto_arm_var.get():
      return

    self.refresh_drives()
    for dev, mount, hw_id, label in self.drives:
      if self.verify_drive_key(dev, mount, hw_id):
        self._arm_specific_drive(dev, hw_id, label)
        break

  def toggle_monitoring(self):
    if not self.monitoring:
      selection = self.drive_listbox.curselection()
      if not selection or not self.drives:
        messagebox.showwarning(
            "Select a Drive", "Please select a valid USB drive from the list."
        )
        return

      selected_device, selected_mount, hw_id, label = self.drives[selection[0]]

      if not self.verify_drive_key(selected_device, selected_mount, hw_id):
        AuditLogger.log(
            "REJECTED",
            f"Rejected unverified/revoked drive {selected_device} [SN: {hw_id}].",
        )
        self.refresh_audit_log_ui()
        messagebox.showerror(
            "Invalid or Unregistered Key",
            "This Drive cannot be used as a secure key.\n\n"
            "(Either it hasn't been set up yet, its key was revoked, or the file was cloned).",
        )
        return

      self.auto_arm_var.set(True)
      self._on_settings_change()
      self._arm_specific_drive(selected_device, hw_id, label)
    else:
      if self.verify_disarm_password():
        self.auto_arm_var.set(False)
        self._on_settings_change()
        AuditLogger.log(
            "DISARMED",
            f"Protection manually disarmed by user for {self.monitored_device}.",
        )
        self.stop_monitoring()

  def stop_monitoring(self):
    self.monitoring = False
    self.grace_active = False
    self.monitored_device = None
    self.monitored_hw_id = None
    self._stop_tray_icon()

    self.badge_lbl.configure(text="● STANDBY (IDLE)", fg_color="#1F538D")
    self.monitor_btn.configure(
        text="🛡️ Verify & Arm Lock",
        fg_color=["#3B8ED0", "#1F6AA5"],
        hover_color=["#36719F", "#144870"],
    )
    self.refresh_btn.configure(state="normal")
    self.setup_btn.configure(state="normal")
    self.pw_btn.configure(state="normal")
    self.drive_listbox.config(state=tk.NORMAL)
    self.status_var.set("Status: Idle (Disarmed)")
    self.refresh_drives()
    self.refresh_audit_log_ui()

  # --- GRACE PERIOD OVERLAY & SYSTEM ACTIONS ---
  def on_usb_removed_event(self, dev_name: str):
    grace_seconds = GRACE_PERIODS.get(self.config.grace_label, 0)
    if grace_seconds <= 0:
      self.execute_security_action(dev_name)
    else:
      self.root.after(0, self._start_grace_countdown, dev_name, grace_seconds)

  def _start_grace_countdown(self, dev_name: str, seconds: int):
    if self.grace_active:
      return
    self.grace_active = True
    self.grace_remaining = seconds
    AuditLogger.log(
        "WARNING",
        f"USB key {dev_name} unplugged! Grace countdown ({seconds}s) started.",
    )

    self.grace_window = ctk.CTkToplevel(self.root)
    self.grace_window.title("⚠️ SECURITY KEY UNPLUGGED")
    self.grace_window.geometry("460x190")
    self.grace_window.attributes("-topmost", True)
    self.grace_window.configure(fg_color="#5C1010")
    self.grace_window.resizable(False, False)

    ctk.CTkLabel(
        self.grace_window,
        text="⚠️ HARDWARE USB KEY REMOVED!",
        font=ctk.CTkFont(size=18, weight="bold"),
        text_color="#FFFFFF",
    ).pack(pady=(20, 6))

    self.grace_countdown_lbl = ctk.CTkLabel(
        self.grace_window,
        text=f"Executing '{self.config.action_mode}' in {self.grace_remaining}s...",
        font=ctk.CTkFont(size=15, weight="bold"),
        text_color="#FFD166",
    )
    self.grace_countdown_lbl.pack(pady=6)

    ctk.CTkLabel(
        self.grace_window,
        text="Plug your USB security key back in immediately to cancel!",
        font=ctk.CTkFont(size=12),
        text_color="#E0E0E0",
    ).pack(pady=(4, 15))

    self._tick_grace_countdown(dev_name)

  def _tick_grace_countdown(self, dev_name: str):
    if not self.grace_active:
      return
    if self.grace_remaining <= 0:
      self._close_grace_window()
      self.execute_security_action(dev_name)
      return

    if OS_TYPE == "Windows":
      try:
        winsound.Beep(1200, 180)
      except Exception:
        pass

    if self.grace_window and self.grace_window.winfo_exists():
      self.grace_countdown_lbl.configure(
          text=f"Executing '{self.config.action_mode}' in {self.grace_remaining}s..."
      )
    self.grace_remaining -= 1
    self.root.after(1000, self._tick_grace_countdown, dev_name)

  def _cancel_grace_countdown(self, dev_name: str):
    self.grace_active = False
    self._close_grace_window()
    self.monitored_device = dev_name
    AuditLogger.log(
        "RECOVERED",
        f"USB key {dev_name} reconnected during grace period. Lock cancelled.",
    )
    self.refresh_audit_log_ui()

  def _close_grace_window(self):
    if self.grace_window is not None:
      try:
        self.grace_window.destroy()
      except Exception:
        pass
      self.grace_window = None

  def _mute_windows_audio(self):
    """Sends the native Windows Virtual-Key Volume Mute toggle."""
    if OS_TYPE == "Windows":
      VK_VOLUME_MUTE = 0xAD
      ctypes.windll.user32.keybd_event(VK_VOLUME_MUTE, 0, 0, 0)
      ctypes.windll.user32.keybd_event(VK_VOLUME_MUTE, 0, 2, 0)

  def execute_security_action(self, dev_name: str):
    """Triggers the configured OS protection action immediately."""
    mode = self.config.action_mode
    AuditLogger.log(
        "LOCK_TRIGGERED",
        f"USB key {dev_name} removed! Executed action: '{mode}'.",
    )

    if OS_TYPE == "Windows":
      if mode == "Lock Screen":
        ctypes.windll.user32.LockWorkStation()
      elif mode == "Lock + Mute Audio":
        self._mute_windows_audio()
        ctypes.windll.user32.LockWorkStation()
      elif mode == "Hibernate / Sleep PC":
        ctypes.windll.user32.LockWorkStation()
        subprocess.run(
            ["rundll32.exe", "powrprof.dll,SetSuspendState", "0,1,0"],
            check=False,
        )
      elif mode == "Force Shutdown (Dead Man's Switch)":
        subprocess.run(["shutdown", "/s", "/f", "/t", "0"], check=False)
    elif OS_TYPE == "Linux":
      subprocess.run(["loginctl", "lock-session"], check=False)

    self.root.after(0, self._post_lock_cleanup, dev_name)

  def _post_lock_cleanup(self, dev_name: str):
    self.stop_monitoring()
    self._restore_window()
    self.status_var.set(
        f"Action '{self.config.action_mode}' executed ({dev_name} removed). Plug key in to Auto-Arm!"
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

          # EventType 3 = Device Removal
          if (
              event_type == 3
              and self.monitoring
              and not self.grace_active
              and self.monitored_device
          ):
            if drive_name.upper() == self.monitored_device.upper():
              self.on_usb_removed_event(self.monitored_device)

          # EventType 2 = Device Arrival (USB Plugged In)
          elif event_type == 2:
            time.sleep(0.35)
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
          and not self.grace_active
          and device.device_node == self.monitored_device
      ):
        self.on_usb_removed_event(self.monitored_device)
      elif device.action == "add":
        time.sleep(0.5)
        self.root.after(0, self._check_existing_drives_for_auto_arm)


if __name__ == "__main__":
  # Prevent multiple instances on Windows using a kernel Named Mutex
  mutex = None
  if OS_TYPE == "Windows":
    # Must set AppUserModelID BEFORE creating the root window so the Taskbar uses our icon!
    try:
      ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
          f"SecuritySuite.{APP_NAME}.{APP_VERSION}"
      )
    except Exception:
      pass

    mutex = ctypes.windll.kernel32.CreateMutexW(
        None, False, "Global\\USBKeyLock_SingleInstance_Mutex"
    )
    if ctypes.windll.kernel32.GetLastError() == 183:
      ctypes.windll.user32.MessageBoxW(
          0,
          "USBKeyLock is already running! Check your Windows System Tray (by the clock).",
          "USBKeyLock Already Running",
          0x40,
      )
      sys.exit(0)

  # Ensure app_icon.ico is generated before window starts
  ensure_icon_file()

  start_min = "--minimized" in sys.argv
  root = ctk.CTk()
  app = USBMonitorApp(root, start_minimized=start_min)
  root.mainloop()
