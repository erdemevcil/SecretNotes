import secrets
import tkinter
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from tkinter import messagebox

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def show_message(message):
    messagebox.showinfo("Secret Notes", message)


BACKEND = default_backend()
ITERATIONS = 100_000


def _derive_key(password: bytes, salt: bytes, iterations=ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=BACKEND)
    return b64e(kdf.derive(password))


def password_encrypt(message: bytes, password: str, iterations: int = ITERATIONS) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )


def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iteration, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iteration, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def encryption_button_click():
    caption = caption_input.get()
    content = content_input.get("1.0", tkinter.END)  # read all lines
    content_input.delete("1.0", tkinter.END)  # delete all lines
    content_bytes = bytes(content, "utf-8")  # convert to bytes
    content_encryption = password_encrypt(content_bytes, password_input.get())
    content_result = bytes.decode(content_encryption, "utf-8")

    with open("Secret Files.txt", "a+") as file:
        file.writelines(caption)
        file.writelines("\n")
        file.writelines(content_result)
        file.writelines("\n")


def decryption_button_click():
    caption = caption_input.get()

    with open("Secret Files.txt") as file:
        file_lines = file.readlines()

    for i in range(len(file_lines) - 1):
        line = file_lines[i].replace("\n", "")
        if line == caption:
            content = password_decrypt(bytes(file_lines[i + 1], "utf-8"), password_input.get())
            content_input.delete("1.0", tkinter.END)
            content_input.insert("1.0", bytes.decode(content, "utf-8"))
            break


# window
window = tkinter.Tk()
window.config(bg="azure")
window.minsize(700, 570)
window.title("Secret Notes")

# title caption
caption_title = tkinter.Label(text="Enter caption")
caption_title.config(bg="azure")
caption_title.place(x=15, y=15)

# input caption
caption_input = tkinter.Entry()
caption_input.place(x=18, y=40)

# title password
password_title = tkinter.Label(text="Enter password")
password_title.config(bg="azure")
password_title.place(x=180, y=15)

# input password
password_input = tkinter.Entry()
password_input.place(x=183, y=40)

# title content
content_title = tkinter.Label(text="Enter your secret note")
content_title.config(bg="azure")
content_title.place(x=15, y=90)

# input content
content_input = tkinter.Text()
content_input.place(x=18, y=115)

# encryption and save button
encryption_button = tkinter.Button(width=20, command=encryption_button_click)
encryption_button.config(text="Encrypt and Save")
encryption_button.place(x=18, y=520)

# decryption and show button
decryption_button = tkinter.Button(width=20)
decryption_button.config(text="Decrypt and Show", command=decryption_button_click)
decryption_button.place(x=200, y=520)

window.mainloop()
