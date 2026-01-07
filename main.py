import os
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend


# =========================
# CRYPTO CORE
# =========================

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_seed(seed: str, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)

    f1 = Fernet(key)
    f2 = Fernet(key)

    layer1 = f1.encrypt(seed.encode())
    layer2 = f2.encrypt(layer1)

    return salt + layer2


def decrypt_seed(data: bytes, password: str) -> str:
    salt = data[:16]
    encrypted = data[16:]

    key = derive_key(password, salt)
    f1 = Fernet(key)
    f2 = Fernet(key)

    layer1 = f2.decrypt(encrypted)
    original = f1.decrypt(layer1)

    return original.decode()


# =========================
# UI
# =========================

class SeedlightApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Seedlight")
        self.geometry("520x420")
        self.resizable(False, False)

        style = ttk.Style(self)
        style.theme_use("clam")

        self.create_widgets()

    def create_widgets(self):
        title = ttk.Label(self, text="Seedlight", font=("Segoe UI", 20, "bold"))
        title.pack(pady=10)

        subtitle = ttk.Label(
            self,
            text="Secure encrypted storage for crypto seed phrases",
            font=("Segoe UI", 10)
        )
        subtitle.pack(pady=5)

        frame = ttk.Frame(self)
        frame.pack(padx=20, pady=20, fill="x")

        ttk.Label(frame, text="Seed Phrase").pack(anchor="w")
        self.seed_text = tk.Text(frame, height=4)
        self.seed_text.pack(fill="x", pady=5)

        ttk.Label(frame, text="Decryption Password (min 8 chars)").pack(anchor="w")
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.pack(fill="x", pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Save .seed", command=self.save_seed).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Open .seed", command=self.open_seed).grid(row=0, column=1, padx=5)

        info = ttk.Label(
            self,
            text="• Files are encrypted locally\n• No data ever leaves your machine",
            font=("Segoe UI", 9),
            foreground="gray"
        )
        info.pack(pady=10)

    def save_seed(self):
        seed = self.seed_text.get("1.0", tk.END).strip()
        password = self.password_entry.get()

        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters.")
            return

        if not seed:
            messagebox.showerror("Error", "Seed phrase is empty.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".seed",
            filetypes=[("Seedlight Files", "*.seed")]
        )

        if not path:
            return

        try:
            encrypted = encrypt_seed(seed, password)
            with open(path, "wb") as f:
                f.write(encrypted)

            messagebox.showinfo("Success", "Seed file saved securely.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_seed(self):
        path = filedialog.askopenfilename(
            filetypes=[("Seedlight Files", "*.seed")]
        )

        if not path:
            return

        password = self.password_entry.get()

        if len(password) < 8:
            messagebox.showerror("Error", "Enter the correct password first.")
            return

        try:
            with open(path, "rb") as f:
                data = f.read()

            seed = decrypt_seed(data, password)
            self.seed_text.delete("1.0", tk.END)
            self.seed_text.insert(tk.END, seed)

            messagebox.showinfo("Success", "Seed decrypted successfully.")

        except Exception:
            messagebox.showerror("Error", "Invalid password or corrupted file.")


if __name__ == "__main__":
    app = SeedlightApp()
    app.mainloop()
