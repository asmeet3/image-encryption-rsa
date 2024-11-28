import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import threading
import random
from math import gcd
from sympy import isprime
import os
import numpy as np


# Function Definitions (unchanged)
def generate_large_primes(bit_length=512):
    def generate_prime_candidate(bit_length):
        candidate = random.getrandbits(bit_length)
        candidate |= (1 << bit_length - 1) | 1
        return candidate

    def generate_prime(bit_length):
        while True:
            candidate = generate_prime_candidate(bit_length)
            if isprime(candidate):
                return candidate

    p = generate_prime(bit_length)
    q = generate_prime(bit_length)
    while p == q:
        q = generate_prime(bit_length)
    return p, q


def calculate_n_and_totient(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    return n, phi_n


def generate_e_and_d(phi_n):
    while True:
        e = random.randint(2, phi_n - 1)
        if gcd(e, phi_n) == 1:
            break
    d = pow(e, -1, phi_n)
    return e, d


def image_to_binary_rgb(image_path):
    img = Image.open(image_path)
    pixel_array = np.array(img)
    binary_pixels = []
    for row in pixel_array:
        binary_row = []
        for pixel in row:
            binary_pixel = [format(value, '08b') for value in pixel]  # Process R, G, B values
            binary_row.append(binary_pixel)
        binary_pixels.append(binary_row)
    return binary_pixels, pixel_array.shape


def encrypt_image_binary(binary_code, e, n):
    ciphertext = []
    for row in binary_code:
        encrypted_row = []
        for pixel in row:
            encrypted_pixel = [pow(int(value, 2), e, n) for value in pixel]
            encrypted_row.append(encrypted_pixel)
        ciphertext.append(encrypted_row)
    return ciphertext


def decrypt_image_binary(ciphertext, d, n):
    plaintext_binary = []
    for row in ciphertext:
        decrypted_row = []
        for pixel in row:
            decrypted_pixel = [format(pow(value, d, n), '08b') for value in pixel]
            decrypted_row.append(decrypted_pixel)
        plaintext_binary.append(decrypted_row)
    return plaintext_binary


def binary_to_image_rgb(binary_data, image_shape, output_path):
    pixel_array = []
    for row in binary_data:
        decoded_row = []
        for pixel in row:
            decoded_pixel = [int(value, 2) for value in pixel]  # Convert binary to RGB values
            decoded_row.append(decoded_pixel)
        pixel_array.append(decoded_row)
    pixel_array = np.array(pixel_array, dtype=np.uint8).reshape(image_shape)
    img = Image.fromarray(pixel_array)
    img.save(output_path)


def save_encrypted_image(ciphertext, image_shape, output_path):
    encrypted_pixels = []
    for row in ciphertext:
        encrypted_row = []
        for pixel in row:
            encrypted_pixel = [value % 256 for value in pixel]
            encrypted_row.append(encrypted_pixel)
        encrypted_pixels.append(encrypted_row)

    encrypted_array = np.array(encrypted_pixels, dtype=np.uint8).reshape(image_shape)
    encrypted_img = Image.fromarray(encrypted_array)
    encrypted_img.save(output_path)
    print(f"Encrypted image saved to {output_path}")


# GUI Implementation
class RSAImageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Image Encryption and Decryption")
        self.root.geometry("600x400")

        self.image_path = None
        self.ciphertext = None
        self.keys = None

        # UI Elements
        self.select_button = ttk.Button(root, text="Select Image", command=self.select_image, bootstyle=PRIMARY)
        self.select_button.pack(pady=10)

        self.image_label = ttk.Label(root, text="No Image Selected", anchor="center")
        self.image_label.pack(pady=10)

        self.encrypt_button = ttk.Button(root, text="Encrypt Image", command=self.start_encrypt_thread, state=DISABLED, bootstyle=SUCCESS)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = ttk.Button(root, text="Decrypt Image", command=self.start_decrypt_thread, state=DISABLED, bootstyle=INFO)
        self.decrypt_button.pack(pady=10)

        self.status_label = ttk.Label(root, text="Status: Waiting for input", bootstyle=INFO)
        self.status_label.pack(pady=10)

        self.loading_label = ttk.Label(root, text="", bootstyle="info")
        self.loading_label.pack(pady=10)

    def show_loading(self):
        self.loading_label.configure(text="Processing... Please wait.", bootstyle="warning")

    def hide_loading(self):
        self.loading_label.configure(text="")

    def select_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.png;*.bmp")])
        if self.image_path:
            img = Image.open(self.image_path)
            img.thumbnail((200, 200))
            img = ImageTk.PhotoImage(img)
            self.image_label.configure(image=img, text="")
            self.image_label.image = img
            self.encrypt_button.config(state=NORMAL)
            self.status_label.config(text="Status: Image loaded", bootstyle="success")

    def start_encrypt_thread(self):
        threading.Thread(target=self.encrypt_image).start()

    def start_decrypt_thread(self):
        threading.Thread(target=self.decrypt_image).start()

    def encrypt_image(self):
        self.show_loading()
        try:
            if not self.image_path:
                messagebox.showerror("Error", "No image selected")
                return

            image_name = os.path.splitext(os.path.basename(self.image_path))[0]

            # Generate RSA keys
            p, q = generate_large_primes(bit_length=64)
            n, phi_n = calculate_n_and_totient(p, q)
            e, d = generate_e_and_d(phi_n)
            self.keys = (e, d, n)

            # Save keys to files
            with open(f"{image_name}_public_key.txt", "w") as pub_file:
                pub_file.write(f"e: {e}\nn: {n}\n")
            with open(f"{image_name}_private_key.txt", "w") as priv_file:
                priv_file.write(f"d: {d}\nn: {n}\n")

            # Convert image to binary and encrypt
            binary_code, shape = image_to_binary_rgb(self.image_path)
            self.ciphertext = encrypt_image_binary(binary_code, e, n)

            # Save encrypted image
            save_encrypted_image(self.ciphertext, shape, f"{image_name}_encrypted.png")
            self.status_label.config(text=f"Status: Encryption complete ({image_name}_encrypted.png)", bootstyle="success")
            self.decrypt_button.config(state=NORMAL)
        finally:
            self.hide_loading()

    def decrypt_image(self):
        self.show_loading()
        try:
            if not self.ciphertext:
                messagebox.showerror("Error", "No encrypted data available")
                return

            # Ask user to select private key file
            private_key_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
            if not private_key_path:
                messagebox.showerror("Error", "No private key file selected")
                return

            # Load private key
            with open(private_key_path, "r") as priv_file:
                lines = priv_file.readlines()
                d = int(lines[0].split(":")[1].strip())
                n = int(lines[1].split(":")[1].strip())

            binary_code = decrypt_image_binary(self.ciphertext, d, n)
            _, shape = image_to_binary_rgb(self.image_path)
            binary_to_image_rgb(binary_code, shape, "decrypted_image.jpg")

            decrypted_img = Image.open("decrypted_image.jpg")
            decrypted_img.thumbnail((200, 200))
            decrypted_img = ImageTk.PhotoImage(decrypted_img)
            self.image_label.configure(image=decrypted_img)
            self.image_label.image = decrypted_img
            self.status_label.config(text="Status: Decryption complete (decrypted_image.jpg)", bootstyle="success")
            messagebox.showinfo("Success", "Decrypted image saved as 'decrypted_image.jpg'")
        finally:
            self.hide_loading()


# Run the GUI application
if __name__ == "__main__":
    root = ttk.Window(themename="darkly")  # Use darkly theme from ttkbootstrap
    app = RSAImageApp(root)
    root.mainloop()
