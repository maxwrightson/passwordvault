"""
Build exe: py -m PyInstaller --onefile --windowed --name PasswordVault password_vault.py
"""

import base64
import json
import os
import secrets
import string
import sys
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_NAME = "Password Vault"
SYMBOLS = '!@#$%^&*()<>:"'
MASK = "**********"
KDF_ITERATIONS = 600_000

NAME_W = 180
USER_W = 380
PASS_W = 130
DATE_W = 130
ROW_H = 40
HEADER_H = 34

BG = "#f3f4f7"
SURFACE = "#ffffff"
ROW_ALT = "#edf1f8"
HEADER_BG = "#e3e7ee"
BORDER = "#d4d9e1"
TEXT = "#1d2330"
MUTED = "#687080"
ACCENT = "#2f6fed"
ACCENT_HOVER = "#2459c9"
ACCENT_PRESSED = "#1d4aa8"
DANGER = "#d23c3c"
DANGER_HOVER = "#b32f2f"
DANGER_PRESSED = "#962626"
DANGER_TINT = "#fbeaea"
DANGER_TINT_PRESSED = "#f5d6d6"
HOVER = "#eceff4"
PRESSED = "#dfe3ea"
DISABLED_BG = "#eef0f3"
DISABLED_FG = "#a3a9b3"

FONT = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 10, "bold")
MONO = ("Consolas", 10)
MONO_SMALL = ("Consolas", 9)


# ---------------------------------------------------------------- storage ---

def app_dir():
    """Folder the vault file lives in: next to the .exe, or next to this script."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


VAULT_PATH = os.path.join(app_dir(), "vault.dat")


def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


class Vault:
    """Encrypted file: 16-byte salt followed by a Fernet token of JSON data."""

    def __init__(self, path):
        self.path = path
        self.salt = None
        self.fernet = None
        self.entries = []
        self.deleted = []

    def exists(self):
        return os.path.exists(self.path)

    def create(self, master_password):
        self.salt = os.urandom(16)
        self.fernet = Fernet(derive_key(master_password, self.salt))
        self.entries = []
        self.deleted = []
        self.save()

    def unlock(self, master_password):
        with open(self.path, "rb") as f:
            data = f.read()
        salt, token = data[:16], data[16:]
        fernet = Fernet(derive_key(master_password, salt))
        try:
            plain = fernet.decrypt(token)
        except InvalidToken:
            return False
        self.salt, self.fernet = salt, fernet
        content = json.loads(plain.decode("utf-8"))
        if isinstance(content, list):
            self.entries, self.deleted = content, []
        else:
            self.entries = content.get("entries", [])
            self.deleted = content.get("deleted", [])
        return True

    def save(self):
        content = {"version": 2, "entries": self.entries, "deleted": self.deleted}
        token = self.fernet.encrypt(json.dumps(content).encode("utf-8"))
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(self.salt + token)
        os.replace(tmp, self.path)

    def add(self, name, username, password):
        self.entries.append({"name": name, "username": username, "password": password})
        self.save()

    def update(self, entry, name, username, password):
        entry.update({"name": name, "username": username, "password": password})
        self.save()

    def delete(self, entry):
        """Move an entry to Recently deleted."""
        self.entries = [e for e in self.entries if e is not entry]
        entry["deleted_at"] = datetime.now().isoformat(timespec="seconds")
        self.deleted.append(entry)
        self.save()

    def restore(self, entry):
        self.deleted = [e for e in self.deleted if e is not entry]
        entry.pop("deleted_at", None)
        self.entries.append(entry)
        self.save()

    def purge(self, entry):
        """Permanently remove one entry from Recently deleted."""
        self.deleted = [e for e in self.deleted if e is not entry]
        self.save()

    def purge_all(self):
        self.deleted = []
        self.save()

    def check_password(self, master_password):
        """True if this is the current master password."""
        with open(self.path, "rb") as f:
            data = f.read()
        try:
            Fernet(derive_key(master_password, data[:16])).decrypt(data[16:])
            return True
        except InvalidToken:
            return False

    def change_password(self, new_master_password):
        """Re-encrypt everything with a new salt and a key from the new password."""
        self.salt = os.urandom(16)
        self.fernet = Fernet(derive_key(new_master_password, self.salt))
        self.save()


def generate_password(length=16):
    """16 random characters with at least one lower, upper, digit and symbol."""
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS]
    chars = [secrets.choice(pool) for pool in pools]
    everything = "".join(pools)
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ---------------------------------------------------------------- styling ---

def setup_styles(root):
    root.configure(bg=BG)
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=BG, foreground=TEXT, font=FONT,
                    bordercolor=BORDER, troughcolor=BG)
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=SURFACE)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
    style.configure("Muted.TLabel", foreground=MUTED)
    style.configure("Card.TLabel", background=SURFACE)
    style.configure("CardTitle.TLabel", background=SURFACE, font=("Segoe UI", 17, "bold"))
    style.configure("CardMuted.TLabel", background=SURFACE, foreground=MUTED)

    def button(name, bg, fg, hover, pressed, padding, font=FONT, outlined=True):
        border = BORDER if outlined else bg
        states = [("disabled", DISABLED_BG), ("pressed", pressed), ("active", hover)]
        style.configure(name, background=bg, foreground=fg, bordercolor=border,
                        lightcolor=bg, darkcolor=bg, focuscolor=bg,
                        padding=padding, font=font, relief="raised")
        style.map(name, background=states, lightcolor=states, darkcolor=states,
                  focuscolor=states, foreground=[("disabled", DISABLED_FG)],
                  bordercolor=[("disabled", BORDER)] if outlined else states)

    button("TButton", SURFACE, TEXT, HOVER, PRESSED, (16, 7))
    button("Accent.TButton", ACCENT, "#ffffff", ACCENT_HOVER, ACCENT_PRESSED, (16, 7),
           FONT_BOLD, outlined=False)
    button("Danger.TButton", DANGER, "#ffffff", DANGER_HOVER, DANGER_PRESSED, (14, 7),
           FONT_BOLD, outlined=False)
    button("BigAccent.TButton", ACCENT, "#ffffff", ACCENT_HOVER, ACCENT_PRESSED, (24, 13),
           ("Segoe UI", 12, "bold"), outlined=False)
    button("Big.TButton", SURFACE, TEXT, HOVER, PRESSED, (24, 13), ("Segoe UI", 12))
    button("Small.TButton", SURFACE, TEXT, HOVER, PRESSED, (8, 3), FONT_SMALL)
    button("SmallDanger.TButton", SURFACE, DANGER, DANGER_TINT, DANGER_TINT_PRESSED, (8, 3),
           FONT_SMALL)
    button("Link.TButton", BG, ACCENT, HOVER, PRESSED, (8, 4), FONT_SMALL, outlined=False)
    button("CardLink.TButton", SURFACE, ACCENT, HOVER, PRESSED, (8, 4), FONT_SMALL,
           outlined=False)

    style.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT, bordercolor=BORDER,
                    lightcolor=SURFACE, darkcolor=SURFACE, insertcolor=TEXT, padding=(8, 6))
    style.map("TEntry", bordercolor=[("focus", ACCENT)], lightcolor=[("focus", ACCENT)])

    style.configure("Vertical.TScrollbar", background=HEADER_BG, troughcolor=SURFACE,
                    bordercolor=SURFACE, lightcolor=HEADER_BG, darkcolor=HEADER_BG,
                    arrowcolor=MUTED, gripcount=0)
    style.map("Vertical.TScrollbar", background=[("active", "#cdd3dc")])


def card(parent):
    """A white panel with a thin border. Put widgets in the returned inner frame."""
    outer = tk.Frame(parent, bg=SURFACE, highlightbackground=BORDER, highlightcolor=BORDER,
                     highlightthickness=1)
    inner = ttk.Frame(outer, style="Card.TFrame", padding=32)
    inner.pack(fill="both", expand=True)
    return outer, inner


class ScrollTable(tk.Frame):
    """Fixed-width columns, alternating row colours, scrolls with the mouse wheel."""

    def __init__(self, parent, columns):
        super().__init__(parent, bg=SURFACE, highlightbackground=BORDER, highlightcolor=BORDER,
                         highlightthickness=1)
        self.columns = columns
        self.row_count = 0

        header = tk.Frame(self, bg=HEADER_BG)
        header.pack(fill="x")
        self._cells(header, [h for h, _ in columns], HEADER_BG, HEADER_H, header=True)

        body = tk.Frame(self, bg=SURFACE)
        body.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(body, bg=SURFACE, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.inner = tk.Frame(self.canvas, bg=SURFACE)
        window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>",
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(window, width=e.width))

        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.canvas.bind_all(seq, self._on_mousewheel)

    def _cells(self, row, texts, bg, height, header=False):
        labels = []
        for (_, width), text in zip(self.columns, texts):
            cell = tk.Frame(row, bg=bg, width=width, height=height)
            cell.pack_propagate(False)
            cell.pack(side="left")
            label = tk.Label(cell, text=text, bg=bg, anchor="w",
                             fg=MUTED if header else TEXT,
                             font=("Segoe UI", 9, "bold") if header else FONT)
            label.pack(fill="both", expand=True, padx=(14, 6))
            labels.append(label)
        return labels

    def clear(self):
        for widget in self.inner.winfo_children():
            widget.destroy()
        self.row_count = 0
        self.canvas.yview_moveto(0)

    def add_row(self, texts):
        """Adds a row; returns its cell labels and a frame to put buttons in."""
        bg = SURFACE if self.row_count % 2 == 0 else ROW_ALT
        row = tk.Frame(self.inner, bg=bg)
        row.pack(fill="x")
        labels = self._cells(row, texts, bg, ROW_H)
        actions = tk.Frame(row, bg=bg)
        actions.pack(side="left", padx=(4, 10))
        self.row_count += 1
        return labels, actions

    def show_message(self, text):
        tk.Label(self.inner, text=text, bg=SURFACE, fg=MUTED, font=FONT,
                 anchor="w").pack(fill="x", padx=14, pady=16)

    def _on_mousewheel(self, event):
        if self.canvas.yview() == (0.0, 1.0):
            return
        if event.num == 4 or getattr(event, "delta", 0) > 0:
            self.canvas.yview_scroll(-1, "units")
        else:
            self.canvas.yview_scroll(1, "units")

    def destroy(self):
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.canvas.unbind_all(seq)
        super().destroy()


# -------------------------------------------------------------------- app ---

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1040x580")
        self.minsize(1040, 460)
        setup_styles(self)
        self.vault = Vault(VAULT_PATH)
        self.current = None
        self.show(LoginScreen)

    def show(self, screen_class, **kwargs):
        if self.current is not None:
            self.current.destroy()
        self.current = screen_class(self, **kwargs)
        self.current.pack(fill="both", expand=True, padx=24, pady=20)


class LoginScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.first_run = not app.vault.exists()

        outer, box = card(self)
        outer.place(relx=0.5, rely=0.45, anchor="center")

        if self.first_run:
            title = "Create a master password"
            subtitle = ("This password unlocks your vault. It can't be recovered "
                        "if you forget it, so pick something memorable.")
        else:
            title = "Welcome back"
            subtitle = "Enter your master password to unlock your vault."
        ttk.Label(box, text=title, style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(box, text=subtitle, style="CardMuted.TLabel", wraplength=320,
                  justify="left").pack(anchor="w", pady=(4, 20))

        ttk.Label(box, text="Master password", style="Card.TLabel").pack(anchor="w")
        self.pw_entry = ttk.Entry(box, show="•", width=36, font=FONT)
        self.pw_entry.pack(fill="x", pady=(4, 12))

        self.confirm_entry = None
        if self.first_run:
            ttk.Label(box, text="Type it again", style="Card.TLabel").pack(anchor="w")
            self.confirm_entry = ttk.Entry(box, show="•", width=36, font=FONT)
            self.confirm_entry.pack(fill="x", pady=(4, 12))

        ttk.Button(box, text="Create vault" if self.first_run else "Unlock",
                   style="Accent.TButton", command=self.submit).pack(fill="x", pady=(8, 0))

        self.pw_entry.focus_set()
        app.bind("<Return>", lambda e: self.submit())

    def submit(self):
        password = self.pw_entry.get()
        if self.first_run:
            if len(password) < 8:
                messagebox.showerror(APP_NAME, "Use at least 8 characters for your master password.")
                return
            if password != self.confirm_entry.get():
                messagebox.showerror(APP_NAME, "The two passwords don't match. Type them again.")
                return
            self.app.vault.create(password)
        else:
            self.app.config(cursor="watch")
            self.app.update()
            ok = self.app.vault.unlock(password)
            self.app.config(cursor="")
            if not ok:
                messagebox.showerror(APP_NAME, "Incorrect password.")
                self.pw_entry.delete(0, "end")
                return
        self.app.show(MenuScreen)

    def destroy(self):
        self.app.unbind("<Return>")
        super().destroy()


class MenuScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        outer, box = card(self)
        outer.place(relx=0.5, rely=0.45, anchor="center")

        count = len(app.vault.entries)
        ttk.Label(box, text=APP_NAME, style="CardTitle.TLabel").pack()
        ttk.Label(box, text=f"{count} password{'s' if count != 1 else ''} saved",
                  style="CardMuted.TLabel").pack(pady=(2, 22))
        ttk.Button(box, text="New password", style="BigAccent.TButton", width=20,
                   command=lambda: app.show(EntryScreen)).pack(fill="x", pady=(0, 10))
        ttk.Button(box, text="Browse passwords", style="Big.TButton", width=20,
                   command=lambda: app.show(BrowseScreen)).pack(fill="x")
        ttk.Button(box, text="Change master password", style="CardLink.TButton",
                   command=lambda: app.show(ChangePasswordScreen)).pack(pady=(14, 0))


class ChangePasswordScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app

        outer, box = card(self)
        outer.place(relx=0.5, rely=0.45, anchor="center")

        ttk.Label(box, text="Change master password", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(box, text="Your saved passwords will be re-encrypted with the new one.",
                  style="CardMuted.TLabel", wraplength=320, justify="left").pack(
            anchor="w", pady=(4, 20))

        self.current_entry = self.field(box, "Current master password")
        self.new_entry = self.field(box, "New master password")
        self.confirm_entry = self.field(box, "Type the new password again")

        buttons = ttk.Frame(box, style="Card.TFrame")
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Back", command=lambda: app.show(MenuScreen)).pack(side="left")
        ttk.Button(buttons, text="Change password", style="Accent.TButton",
                   command=self.submit).pack(side="right")

        self.current_entry.focus_set()
        app.bind("<Return>", lambda e: self.submit())

    @staticmethod
    def field(parent, label):
        ttk.Label(parent, text=label, style="Card.TLabel").pack(anchor="w")
        entry = ttk.Entry(parent, show="•", width=36, font=FONT)
        entry.pack(fill="x", pady=(4, 12))
        return entry

    def submit(self):
        new = self.new_entry.get()
        if len(new) < 8:
            messagebox.showerror(APP_NAME, "Use at least 8 characters for your new master password.")
            return
        if new != self.confirm_entry.get():
            messagebox.showerror(APP_NAME, "The two new passwords don't match. Type them again.")
            return

        self.app.config(cursor="watch")
        self.app.update()
        correct = self.app.vault.check_password(self.current_entry.get())
        if correct:
            self.app.vault.change_password(new)
        self.app.config(cursor="")

        if not correct:
            messagebox.showerror(APP_NAME, "Your current master password is incorrect.")
            self.current_entry.delete(0, "end")
            self.current_entry.focus_set()
            return
        messagebox.showinfo(APP_NAME, "Your master password has been changed.")
        self.app.show(MenuScreen)

    def destroy(self):
        self.app.unbind("<Return>")
        super().destroy()


class EntryScreen(ttk.Frame):
    """Used for adding a new entry, or editing one when `entry` is given."""

    def __init__(self, app, entry=None):
        super().__init__(app)
        self.app = app
        self.entry = entry
        editing = entry is not None
        back_to = BrowseScreen if editing else MenuScreen

        outer, box = card(self)
        outer.place(relx=0.5, rely=0.45, anchor="center")

        ttk.Label(box, text="Edit password" if editing else "New password",
                  style="CardTitle.TLabel").grid(row=0, column=0, columnspan=2, sticky="w",
                                                 pady=(0, 18))

        self.name_var = tk.StringVar(value=entry["name"] if editing else "")
        self.user_var = tk.StringVar(value=entry["username"] if editing else "")
        self.pw_var = tk.StringVar(value=entry["password"] if editing else "")
        fields = [("Name", self.name_var, FONT),
                  ("Username / email", self.user_var, FONT),
                  ("Password", self.pw_var, MONO)]

        row = 1
        for label, var, font in fields:
            ttk.Label(box, text=label, style="Card.TLabel").grid(row=row, column=0, columnspan=2,
                                                                sticky="w")
            field = ttk.Entry(box, textvariable=var, width=40, font=font)
            field.grid(row=row + 1, column=0, sticky="ew", pady=(4, 14))
            if row == 1:
                field.focus_set()
            var.trace_add("write", self.update_confirm_state)
            row += 2

        ttk.Button(box, text="Generate", command=self.generate).grid(
            row=row - 1, column=1, sticky="n", padx=(8, 0), pady=(4, 14))

        buttons = ttk.Frame(box, style="Card.TFrame")
        buttons.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        ttk.Button(buttons, text="Back", command=lambda: app.show(back_to)).pack(side="left")
        self.confirm_btn = ttk.Button(buttons, text="Save changes" if editing else "Confirm",
                                      style="Accent.TButton", command=self.confirm)
        self.confirm_btn.pack(side="right")

        box.columnconfigure(0, weight=1)
        self.update_confirm_state()

    def all_filled(self):
        return all(v.get().strip() for v in (self.name_var, self.user_var, self.pw_var))

    def update_confirm_state(self, *_):
        self.confirm_btn.config(state="normal" if self.all_filled() else "disabled")

    def generate(self):
        self.pw_var.set(generate_password())

    def confirm(self):
        if not self.all_filled():
            return
        values = (self.name_var.get().strip(), self.user_var.get().strip(), self.pw_var.get())
        if self.entry is None:
            self.app.vault.add(*values)
            self.app.show(MenuScreen)
        else:
            self.app.vault.update(self.entry, *values)
            self.app.show(BrowseScreen)


class BrowseScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app

        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 14))
        ttk.Button(top, text="Back", command=lambda: app.show(MenuScreen)).pack(side="left")
        ttk.Label(top, text="Passwords", style="Title.TLabel").pack(side="left", padx=(16, 0))
        self.search_var = tk.StringVar()
        search = ttk.Entry(top, textvariable=self.search_var, width=30, font=FONT)
        search.pack(side="right")
        ttk.Label(top, text="Search names", style="Muted.TLabel").pack(side="right", padx=(0, 8))
        search.focus_set()
        self.search_var.trace_add("write", lambda *_: self.refresh())

        bottom = ttk.Frame(self)
        bottom.pack(side="bottom", fill="x", pady=(10, 0))
        self.deleted_btn = ttk.Button(bottom, style="Link.TButton",
                                      command=lambda: app.show(DeletedScreen))
        self.deleted_btn.pack(side="left")
        self.count_label = ttk.Label(bottom, style="Muted.TLabel")
        self.count_label.pack(side="right")

        self.table = ScrollTable(self, [("Name", NAME_W), ("Username / email", USER_W),
                                        ("Password", PASS_W)])
        self.table.pack(fill="both", expand=True)
        self.refresh()

    def refresh(self):
        vault = self.app.vault
        self.table.clear()
        self.deleted_btn.config(text=f"Recently deleted ({len(vault.deleted)})")
        count = len(vault.entries)
        self.count_label.config(text=f"{count} password{'s' if count != 1 else ''}")

        query = self.search_var.get().strip().lower()
        matches = sorted((e for e in vault.entries if query in e["name"].lower()),
                         key=lambda e: e["name"].lower())
        if not matches:
            self.table.show_message(
                "No passwords saved yet. Go back and choose New password to add one."
                if not vault.entries else "No names match your search.")

        for entry in matches:
            labels, actions = self.table.add_row([entry["name"], entry["username"], MASK])
            pw_label = labels[2]
            pw_label.config(font=MONO_SMALL)
            pw_label.pack_configure(padx=(14, 2))

            copy_btn = ttk.Button(actions, text="Copy", width=6, style="Small.TButton",
                                  state="disabled")
            copy_btn.configure(command=lambda b=copy_btn, p=entry["password"]: self.copy(b, p))
            show_btn = ttk.Button(actions, text="Show", width=5, style="Small.TButton")
            show_btn.configure(command=lambda l=pw_label, s=show_btn, c=copy_btn,
                               p=entry["password"]: self.toggle(l, s, c, p))
            edit_btn = ttk.Button(actions, text="Edit", width=4, style="Small.TButton",
                                  command=lambda e=entry: self.app.show(EntryScreen, entry=e))
            delete_btn = ttk.Button(actions, text="Delete", width=6, style="SmallDanger.TButton",
                                    command=lambda e=entry: self.delete(e))
            for b in (copy_btn, show_btn, edit_btn, delete_btn):
                b.pack(side="left", padx=2)

    @staticmethod
    def toggle(label, show_btn, copy_btn, password):
        if show_btn.cget("text") == "Show":
            label.config(text=password)
            show_btn.config(text="Hide")
            copy_btn.config(state="normal")
        else:
            label.config(text=MASK)
            show_btn.config(text="Show")
            copy_btn.config(state="disabled", text="Copy")

    def copy(self, button, password):
        self.app.clipboard_clear()
        self.app.clipboard_append(password)
        self.app.update()
        button.config(text="Copied")
        button.after(1500, lambda: button.winfo_exists() and button.config(text="Copy"))

    def delete(self, entry):
        if messagebox.askyesno(APP_NAME, "Delete \"" + entry["name"] + "\"?\n\n"
                               "It will be moved to Recently deleted, where you can restore it."):
            self.app.vault.delete(entry)
            self.refresh()


class DeletedScreen(ttk.Frame):
    def __init__(self, app):
        super().__init__(app)
        self.app = app

        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 6))
        ttk.Button(top, text="Back", command=lambda: app.show(BrowseScreen)).pack(side="left")
        ttk.Label(top, text="Recently deleted", style="Title.TLabel").pack(side="left",
                                                                          padx=(16, 0))
        self.empty_btn = ttk.Button(top, text="Empty recently deleted", style="Danger.TButton",
                                    command=self.purge_all)
        self.empty_btn.pack(side="right")

        ttk.Label(self, text="Items stay here until you restore them or delete them for good.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 12))

        self.table = ScrollTable(self, [("Name", NAME_W), ("Username / email", USER_W),
                                        ("Deleted on", DATE_W)])
        self.table.pack(fill="both", expand=True)
        self.refresh()

    @staticmethod
    def format_date(value):
        try:
            return datetime.fromisoformat(value).strftime("%d %b %Y")
        except (TypeError, ValueError):
            return ""

    def refresh(self):
        deleted = self.app.vault.deleted
        self.table.clear()
        self.empty_btn.config(state="normal" if deleted else "disabled")
        if not deleted:
            self.table.show_message("Nothing here. Deleted passwords will appear here.")

        for entry in sorted(deleted, key=lambda e: e.get("deleted_at", ""), reverse=True):
            _, actions = self.table.add_row([entry["name"], entry["username"],
                                             self.format_date(entry.get("deleted_at"))])
            ttk.Button(actions, text="Restore", width=-8, style="Small.TButton",
                       command=lambda e=entry: self.restore(e)).pack(side="left", padx=3)
            ttk.Button(actions, text="Delete forever", width=-13, style="SmallDanger.TButton",
                       command=lambda e=entry: self.purge(e)).pack(side="left", padx=3)

    def restore(self, entry):
        self.app.vault.restore(entry)
        self.refresh()

    def purge(self, entry):
        if messagebox.askyesno(APP_NAME, "Permanently delete \"" + entry["name"] +
                               "\"? This can't be undone.", icon="warning"):
            self.app.vault.purge(entry)
            self.refresh()

    def purge_all(self):
        n = len(self.app.vault.deleted)
        if messagebox.askyesno(APP_NAME, f"Permanently delete all {n} item{'s' if n != 1 else ''}"
                               " in Recently deleted? This can't be undone.", icon="warning"):
            self.app.vault.purge_all()
            self.refresh()


if __name__ == "__main__":
    App().mainloop()