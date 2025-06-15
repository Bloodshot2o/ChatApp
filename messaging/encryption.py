from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# AES Encryption and Decryption
def encrypt_message(key, plaintext):
    # Create cipher config
    iv = os.urandom(16)  # Random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding plaintext to be a multiple of 128 bits
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the message
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_message  # Return the IV and the ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]  # First 16 bytes are IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the message
    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    # Unpad the message
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return decrypted_message.decode()
