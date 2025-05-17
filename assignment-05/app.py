import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken

# Generate a key (should be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Initialize session state variables for persistence
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted_text: {"passkey": hashed_passkey}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "page" not in st.session_state:
    st.session_state.page = "Home"

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    stored = st.session_state.stored_data.get(encrypted_text)

    if stored and stored["passkey"] == hashed_passkey:
        try:
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        except InvalidToken:
            return None
    else:
        st.session_state.failed_attempts += 1
        return None

# Navigation menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]

# Sync sidebar choice with session_state.page
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.page))
st.session_state.page = choice

# UI Pages
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {"passkey": hashed_passkey}
            st.success("✅ Data stored securely!")
            st.text(f"Encrypted Data: {encrypted_text}")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                attempts_left = max(0, 3 - st.session_state.failed_attempts)
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.page = "Login"
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with secure auth in production
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state.page = "Retrieve Data"
        else:
            st.error("❌ Incorrect password!")

else:
    st.error("⚠️ Invalid page selected!")
