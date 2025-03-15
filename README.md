# ChaCha20
First project on ChaCha20 protocol for encryption messenger tool.

# **ChaCha20 Cipher - Secure Encryption Tool 🔐**  

Welcome to the **ChaCha20 Cipher Encryption Tool**, a lightweight Python-based implementation of the **ChaCha20 stream cipher** for secure message encryption and decryption. This repository provides an easy-to-use **Streamlit** web app that allows users to **encrypt and decrypt** messages using a **256-bit key**.  

---

## **🔑 Features**
✅ **Secure Encryption** – Uses the **ChaCha20** algorithm, known for its speed and security.  
✅ **256-bit Key Support** – Ensures strong encryption with a **user-defined** or **randomly generated** key.  
✅ **Random Nonce Generation** – Prevents replay attacks and enhances security.  
✅ **Base64 Encoding** – Encoded messages are easy to share and copy.  
✅ **Streamlit UI** – User-friendly web interface for encrypting and decrypting messages.  

---

## **📜 How It Works**
1. **Enter a 32-character secret key** (or generate a random one).  
2. **Encrypt a message** – The app generates a nonce and encrypts the text using **ChaCha20**.  
3. **Share the encrypted message** (Base64-encoded for easy sharing).  
4. **Decrypt messages** – Paste the encrypted text and decrypt it using the same secret key.  

---

## **🚀 Installation & Usage**
### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/yourusername/chacha20-cipher.git
cd chacha20-cipher
```

### **2️⃣ Install Dependencies**
```bash
pip install -r requirements.txt
```

### **3️⃣ Run the Streamlit App**
```bash
streamlit run app.py
```

---

## **🛠 Dependencies**
- `streamlit` – For the web UI  
- `cryptography` – Provides the **ChaCha20** encryption algorithm  
- `base64` – Used for encoding and decoding messages  
- `os` & `secrets` – Secure key and nonce generation  

---

## **🔒 Security Notice**
- Use a **strong 32-character key** for maximum security.  
- Never reuse nonces with the same key.  
- ChaCha20 is considered secure, but **keep your key private**!  

---

## **📜 License**
This project is open-source and licensed under the **MIT License**. Feel free to fork and contribute!  

👨‍💻 **Contributions Welcome!** If you have improvements, feel free to submit a PR. 🚀  

---

Let me know if you want any customizations! 🔥
