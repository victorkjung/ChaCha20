import streamlit as st
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def chacha20_encrypt(message: str, key: bytes) -> str:
    """
    Encrypt a message using the ChaCha20 cipher.

    Parameters:
        message (str): The plaintext message to encrypt.
        key (bytes): A 32-byte (256-bit) secret key.

    Returns:
        str: The Base64-encoded ciphertext with nonce.
    """
    nonce = os.urandom(16)  # 16-byte nonce (ChaCha20 normally uses 12, but OpenSSL supports 16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce[:12]), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    return base64.b64encode(nonce + ciphertext).decode()


def chacha20_decrypt(encoded_message: str, key: bytes) -> str:
    """
    Decrypt a message encrypted with the ChaCha20 cipher.

    Parameters:
        encoded_message (str): The Base64-encoded ciphertext with nonce.
        key (bytes): A 32-byte (256-bit) secret key.

    Returns:
        str: The decrypted plaintext message.
    """
    decoded_data = base64.b64decode(encoded_message)
    nonce, ciphertext = decoded_data[:16], decoded_data[16:]
    cipher = Cipher(algorithms.ChaCha20(key, nonce[:12]), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()


def main():
    st.title("ChaCha20 Cipher Messenger")
    st.write("Secure your 🏦 messages with the ChaCha20 🔏 encryption algorithm! 🔐")

    # User enters a key (must be exactly 32 bytes)
    user_key = st.text_input("Enter a 32-character secret key:", type="password")

    if len(user_key) != 32:
        st.warning("The key must be exactly 32 characters long.")
        return

    key_bytes = user_key.encode()  # Convert key to bytes

    # Tabs for encoding and decoding
    tab1, tab2 = st.tabs(["Encrypt Message", "Decrypt Message"])

    # Encryption tab
    with tab1:
        st.header("Encrypt a Message")
        message_to_encrypt = st.text_area("Enter your message to 📫 encrypt:")
        if st.button("Encrypt", key="encrypt_button"):
            if message_to_encrypt:
                encrypted_message = chacha20_encrypt(message_to_encrypt, key_bytes)
                st.success("Encrypted 📮 Message:")
                st.code(encrypted_message)
            else:
                st.error("Please enter a 📧 message to encrypt.")

    # Decryption tab
    with tab2:
        st.header("Decrypt a Message")
        message_to_decrypt = st.text_area("Enter the 📮 encrypted message:")
        if st.button("Decrypt", key="decrypt_button"):
            if message_to_decrypt:
                try:
                    decrypted_message = chacha20_decrypt(message_to_decrypt, key_bytes)
                    st.success("Decrypted Message:")
                    st.code(decrypted_message)
                except Exception:
                    st.error("Decryption 🚷 failed. Check the key or message format.")
            else:
                st.error("Please enter a 📨 message to decrypt.")

    # Sidebar instructions
    st.sidebar.header("How to Use ChaCha20 Cipher Messenger")
    st.sidebar.write("1. Agree on a **32-character key** with your friend.")
    st.sidebar.write("2. Use the 'Encrypt Message' tab to encrypt your 📨 message.")
    st.sidebar.write("3. Share the **Base64-encoded** encrypted message.")
    st.sidebar.write("4. Use the 'Decrypt Message' tab with the same key to decrypt.")
    st.sidebar.write("5. Keep your key **secret** for security! 🔑")


if __name__ == "__main__":
    main()
