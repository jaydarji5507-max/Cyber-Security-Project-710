import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import os
import hashlib
import secrets
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

THUMB_SIZE = (260, 260)

# ============================================================
# SECURITY FUNCTIONS
# ============================================================

def derive_key(password, salt):
    """
    Derive a strong 256-bit key from the password.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        300_000,
        dklen=32
    )


def bytes_to_bits(data):
    return [
        (byte >> i) & 1
        for byte in data
        for i in range(7, -1, -1)
    ]


def bits_to_bytes(bits):
    result = bytearray()

    for i in range(0, len(bits), 8):
        byte = 0

        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit

        result.append(byte)

    return bytes(result)


# ============================================================
# SECURE LSB ENCODE
# ============================================================

def encode_message(image, message, password):
    if not password:
        raise ValueError("Password is required.")

    img = image.convert("RGB")

    width, height = img.size
    pixels = list(img.getdata())

    # Convert message to bytes
    message_bytes = message.encode("utf-8")

    # Random salt and nonce
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)

    # Password -> AES key
    key = derive_key(password, salt)

    # AES-GCM encryption
    aes = AESGCM(key)

    encrypted = aes.encrypt(
        nonce,
        message_bytes,
        None
    )

    # Packet:
    # MAGIC + salt + nonce + encrypted message
    packet = (
        b"STG2"
        + salt
        + nonce
        + encrypted
    )

    bits = bytes_to_bits(packet)

    capacity = width * height * 3

    if len(bits) > capacity:
        max_bytes = (capacity // 8) - 32

        raise ValueError(
            f"Message is too large.\n"
            f"Approximate maximum: {max_bytes:,} bytes"
        )

    # --------------------------------------------------------
    # RANDOMIZED POSITIONS
    # --------------------------------------------------------

    # Create deterministic random positions from password + salt
    seed = hashlib.sha256(
        password.encode("utf-8") + salt
    ).digest()

    seed_int = int.from_bytes(seed, "big")

    import random
    rng = random.Random(seed_int)

    positions = list(range(capacity))
    rng.shuffle(positions)

    selected_positions = positions[:len(bits)]

    # Convert pixels into RGB channel array
    flat = []

    for pixel in pixels:
        flat.extend(pixel)

    # Modify only selected LSB positions
    for pos, bit in zip(selected_positions, bits):
        flat[pos] = (flat[pos] & 0xFE) | bit

    # Rebuild pixels
    new_pixels = []

    for i in range(0, len(flat), 3):
        new_pixels.append(
            (
                flat[i],
                flat[i + 1],
                flat[i + 2]
            )
        )

    output = Image.new("RGB", img.size)
    output.putdata(new_pixels)

    return output


# ============================================================
# SECURE LSB DECODE
# ============================================================

def decode_message(image, password):

    if not password:
        raise ValueError("Password is required.")

    img = image.convert("RGB")

    width, height = img.size
    pixels = list(img.getdata())

    flat = []

    for pixel in pixels:
        flat.extend(pixel)

    capacity = len(flat)

    # --------------------------------------------------------
    # We need at least:
    #
    # MAGIC 4 bytes
    # SALT 16 bytes
    # NONCE 12 bytes
    # AES-GCM tag is included in encrypted data
    # --------------------------------------------------------

    minimum_bits = (4 + 16 + 12 + 16) * 8

    if capacity < minimum_bits:
        raise ValueError("Image is too small.")

    # --------------------------------------------------------
    # We don't know the salt initially.
    #
    # So first try candidate positions generated from
    # password + possible salt.
    #
    # To make extraction practical, we store the salt in
    # a small randomized bootstrap area.
    # --------------------------------------------------------

    # Bootstrap area uses first 32 bytes only for salt.
    # This does NOT contain the secret message.
    bootstrap_bits = []

    for i in range(16 * 8):
        bootstrap_bits.append(flat[i] & 1)

    salt = bits_to_bytes(bootstrap_bits)

    # Validate salt
    if len(salt) != 16:
        raise ValueError("Invalid hidden data.")

    # Generate random positions
    seed = hashlib.sha256(
        password.encode("utf-8") + salt
    ).digest()

    seed_int = int.from_bytes(seed, "big")

    import random
    rng = random.Random(seed_int)

    positions = list(range(16 * 8, capacity))
    rng.shuffle(positions)

    # Need header:
    # MAGIC + salt + nonce + ciphertext
    #
    # First extract enough data for the fixed section.
    fixed_bytes = 4 + 16 + 12

    fixed_bits_needed = fixed_bytes * 8

    fixed_positions = positions[:fixed_bits_needed]

    fixed_bits = [
        flat[p] & 1
        for p in fixed_positions
    ]

    fixed_data = bits_to_bytes(fixed_bits)

    if fixed_data[:4] != b"STG2":
        raise ValueError(
            "No valid encrypted message found.\n"
            "Check the password or image."
        )

    extracted_salt = fixed_data[4:20]
    nonce = fixed_data[20:32]

    # Salt must match bootstrap
    if extracted_salt != salt:
        raise ValueError("Invalid hidden data.")

    # --------------------------------------------------------
    # Extract remaining encrypted data
    # --------------------------------------------------------

    remaining_positions = positions[fixed_bits_needed:]

    encrypted_bits = [
        flat[p] & 1
        for p in remaining_positions
    ]

    encrypted_data = bits_to_bytes(encrypted_bits)

    # Remove trailing incomplete bytes if any
    encrypted_data = encrypted_data[:len(encrypted_data)]

    if len(encrypted_data) < 16:
        raise ValueError("No encrypted message found.")

    key = derive_key(password, salt)

    aes = AESGCM(key)

    try:
        decrypted = aes.decrypt(
            nonce,
            encrypted_data,
            None
        )
    except Exception:
        raise ValueError(
            "Wrong password or corrupted image."
        )

    return decrypted.decode(
        "utf-8",
        errors="replace"
    )


# ============================================================
# GUI
# ============================================================

class SecureStegoApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("Secure LSB Steganography")
        self.geometry("850x700")
        self.minsize(760, 620)

        self.encode_image = None
        self.decode_image = None

        self.encode_thumb = None
        self.decode_thumb = None

        self.build_ui()

    # ========================================================
    # UI
    # ========================================================

    def build_ui(self):

        notebook = ttk.Notebook(self)
        notebook.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        self.encode_tab = ttk.Frame(notebook)
        self.decode_tab = ttk.Frame(notebook)

        notebook.add(
            self.encode_tab,
            text="🔐 Hide Message"
        )

        notebook.add(
            self.decode_tab,
            text="🔓 Extract Message"
        )

        self.build_encode_tab()
        self.build_decode_tab()

    # ========================================================
    # ENCODE TAB
    # ========================================================

    def build_encode_tab(self):

        frame = self.encode_tab

        top = ttk.Frame(frame)
        top.pack(
            fill="x",
            padx=10,
            pady=10
        )

        ttk.Button(
            top,
            text="Select Image",
            command=self.select_encode_image
        ).pack(side="left")

        self.encode_path = ttk.Label(
            top,
            text="No image selected"
        )

        self.encode_path.pack(
            side="left",
            padx=10
        )

        # Preview
        preview_frame = ttk.Frame(frame)
        preview_frame.pack(
            fill="x",
            padx=10,
            pady=10
        )

        self.encode_preview = ttk.Label(
            preview_frame,
            text="Image Preview",
            relief="groove",
            anchor="center"
        )

        self.encode_preview.pack(side="left")

        self.encode_info = ttk.Label(
            preview_frame,
            text="",
            justify="left"
        )

        self.encode_info.pack(
            side="left",
            padx=20
        )

        ttk.Label(
            frame,
            text="Secret Message:"
        ).pack(
            anchor="w",
            padx=10
        )

        self.message_box = scrolledtext.ScrolledText(
            frame,
            height=10,
            wrap="word"
        )

        self.message_box.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=5
        )

        ttk.Label(
            frame,
            text="Password:"
        ).pack(
            anchor="w",
            padx=10
        )

        self.encode_password = ttk.Entry(
            frame,
            show="•"
        )

        self.encode_password.pack(
            fill="x",
            padx=10,
            pady=5
        )

        self.show_encode_password = ttk.Checkbutton(
            frame,
            text="Show password",
            command=self.toggle_encode_password
        )

        self.show_encode_password.pack(
            anchor="w",
            padx=10
        )

        ttk.Button(
            frame,
            text="🔐 Encrypt & Hide Message",
            command=self.do_encode
        ).pack(
            padx=10,
            pady=15
        )

        self.encode_status = ttk.Label(
            frame,
            text=""
        )

        self.encode_status.pack(
            padx=10,
            pady=5
        )

    # ========================================================
    # DECODE TAB
    # ========================================================

    def build_decode_tab(self):

        frame = self.decode_tab

        top = ttk.Frame(frame)
        top.pack(
            fill="x",
            padx=10,
            pady=10
        )

        ttk.Button(
            top,
            text="Select Image",
            command=self.select_decode_image
        ).pack(side="left")

        self.decode_path = ttk.Label(
            top,
            text="No image selected"
        )

        self.decode_path.pack(
            side="left",
            padx=10
        )

        preview_frame = ttk.Frame(frame)
        preview_frame.pack(
            fill="x",
            padx=10,
            pady=10
        )

        self.decode_preview = ttk.Label(
            preview_frame,
            text="Image Preview",
            relief="groove",
            anchor="center"
        )

        self.decode_preview.pack(side="left")

        ttk.Label(
            frame,
            text="Password:"
        ).pack(
            anchor="w",
            padx=10
        )

        self.decode_password = ttk.Entry(
            frame,
            show="•"
        )

        self.decode_password.pack(
            fill="x",
            padx=10,
            pady=5
        )

        ttk.Button(
            frame,
            text="🔓 Decrypt & Extract",
            command=self.do_decode
        ).pack(
            padx=10,
            pady=10
        )

        ttk.Label(
            frame,
            text="Extracted Message:"
        ).pack(
            anchor="w",
            padx=10
        )

        self.extracted = scrolledtext.ScrolledText(
            frame,
            height=12,
            wrap="word",
            state="disabled"
        )

        self.extracted.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=5
        )

        self.decode_status = ttk.Label(
            frame,
            text=""
        )

        self.decode_status.pack(
            padx=10,
            pady=5
        )

    # ========================================================
    # PASSWORD VISIBILITY
    # ========================================================

    def toggle_encode_password(self):

        if self.show_encode_password.instate(["selected"]):
            self.encode_password.config(show="")
        else:
            self.encode_password.config(show="•")

    # ========================================================
    # SELECT ENCODE IMAGE
    # ========================================================

    def select_encode_image(self):

        path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[
                (
                    "Image files",
                    "*.png *.bmp *.tiff *.tif"
                ),
                (
                    "All files",
                    "*.*"
                )
            ]
        )

        if not path:
            return

        try:
            image = Image.open(path)

        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Could not open image:\n{e}"
            )
            return

        self.encode_image = image

        self.encode_path.config(
            text=os.path.basename(path)
        )

        thumb = image.copy()
        thumb.thumbnail(THUMB_SIZE)

        self.encode_thumb = ImageTk.PhotoImage(thumb)

        self.encode_preview.config(
            image=self.encode_thumb,
            text=""
        )

        capacity = (
            image.width *
            image.height *
            3
        ) // 8

        self.encode_info.config(
            text=(
                f"Resolution: {image.width} × {image.height}\n"
                f"Approx capacity: {capacity:,} bytes\n\n"
                f"Security:\n"
                f"• AES-256-GCM\n"
                f"• Randomized LSB positions\n"
                f"• Password protected"
            )
        )

    # ========================================================
    # SELECT DECODE IMAGE
    # ========================================================

    def select_decode_image(self):

        path = filedialog.askopenfilename(
            title="Select Encoded Image",
            filetypes=[
                (
                    "Image files",
                    "*.png *.bmp *.tiff *.tif"
                ),
                (
                    "All files",
                    "*.*"
                )
            ]
        )

        if not path:
            return

        try:
            image = Image.open(path)

        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Could not open image:\n{e}"
            )
            return

        self.decode_image = image

        self.decode_path.config(
            text=os.path.basename(path)
        )

        thumb = image.copy()
        thumb.thumbnail(THUMB_SIZE)

        self.decode_thumb = ImageTk.PhotoImage(thumb)

        self.decode_preview.config(
            image=self.decode_thumb,
            text=""
        )

        self.extracted.config(state="normal")
        self.extracted.delete("1.0", "end")
        self.extracted.config(state="disabled")

    # ========================================================
    # ENCODE
    # ========================================================

    def do_encode(self):

        if self.encode_image is None:
            messagebox.showwarning(
                "Image Required",
                "Please select an image."
            )
            return

        message = self.message_box.get(
            "1.0",
            "end-1c"
        )

        password = self.encode_password.get()

        if not message:
            messagebox.showwarning(
                "Message Required",
                "Please enter a secret message."
            )
            return

        if len(password) < 8:
            messagebox.showwarning(
                "Weak Password",
                "Use a password with at least 8 characters."
            )
            return

        try:
            result = encode_message(
                self.encode_image,
                message,
                password
            )

        except Exception as e:
            messagebox.showerror(
                "Encoding Error",
                str(e)
            )
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Secure Image",
            defaultextension=".png",
            filetypes=[
                ("PNG Image", "*.png"),
                ("BMP Image", "*.bmp"),
                ("TIFF Image", "*.tiff")
            ]
        )

        if not save_path:
            return

        try:
            result.save(save_path)

        except Exception as e:
            messagebox.showerror(
                "Save Error",
                str(e)
            )
            return

        self.encode_status.config(
            text="✔ Message encrypted and hidden successfully.",
            foreground="green"
        )

        messagebox.showinfo(
            "Success",
            "Message encrypted and hidden successfully!"
        )

    # ========================================================
    # DECODE
    # ========================================================

    def do_decode(self):

        if self.decode_image is None:
            messagebox.showwarning(
                "Image Required",
                "Please select an encoded image."
            )
            return

        password = self.decode_password.get()

        if not password:
            messagebox.showwarning(
                "Password Required",
                "Enter the password."
            )
            return

        try:
            message = decode_message(
                self.decode_image,
                password
            )

        except Exception as e:
            messagebox.showerror(
                "Extraction Failed",
                str(e)
            )
            return

        self.extracted.config(
            state="normal"
        )

        self.extracted.delete(
            "1.0",
            "end"
        )

        self.extracted.insert(
            "1.0",
            message
        )

        self.extracted.config(
            state="disabled"
        )

        self.decode_status.config(
            text="✔ Message decrypted successfully.",
            foreground="green"
        )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    app = SecureStegoApp()

    app.mainloop()