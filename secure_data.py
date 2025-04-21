

import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid

# -------------------------🔧 Session Initialization -------------------------
if 'error_count' not in st.session_state:
    st.session_state.error_count = 0

if 'secure_store' not in st.session_state:
    st.session_state.secure_store = {}

if 'active_screen' not in st.session_state:
    st.session_state.active_screen = "Dashboard"

if 'last_error_time' not in st.session_state:
    st.session_state.last_error_time = 0

# -------------------------🔐 Security Utilities -------------------------

def create_hash(passcode):
    """Generate SHA-256 hash of passcode."""
    return hashlib.sha256(passcode.encode()).hexdigest()

def derive_key(passcode):
    """Derive a Fernet-compatible encryption key from passcode."""
    hash_digest = hashlib.sha256(passcode.encode()).digest()
    return base64.urlsafe_b64encode(hash_digest[:32])

def lock_data(plain_text, passcode):
    """Encrypt user input using Fernet and passcode."""
    key = derive_key(passcode)
    fernet = Fernet(key)
    return fernet.encrypt(plain_text.encode()).decode()

def unlock_data(cipher_text, passcode, key_id):
    """Attempt to decrypt user data with given passcode and entry ID."""
    try:
        hashed_key = create_hash(passcode)
        if key_id in st.session_state.secure_store and \
           st.session_state.secure_store[key_id]["passcode"] == hashed_key:

            key = derive_key(passcode)
            decrypted = Fernet(key).decrypt(cipher_text.encode()).decode()
            st.session_state.error_count = 0
            return decrypted
        else:
            st.session_state.error_count += 1
            st.session_state.last_error_time = time.time()
            return None
    except Exception:
        st.session_state.error_count += 1
        st.session_state.last_error_time = time.time()
        return None

def create_unique_id():
    """Generate a new unique ID for each stored item."""
    return str(uuid.uuid4())

def clear_error_log():
    """Reset failed attempt counter."""
    st.session_state.error_count = 0

def switch_screen(screen):
    """Change currently active screen."""
    st.session_state.active_screen = screen


# -------------------------📱 App UI Layout -------------------------

st.title("🔐 Encrypted Info Vault")

st.markdown("""
Welcome to your **Secure Data Locker** 🔒  
Store and access sensitive information using custom passcodes, protected by AES encryption under the hood.
""")

menu = ["Dashboard", "Save Info", "Access Info", "Admin Login"]
user_choice = st.sidebar.selectbox("📂 Menu", menu, index=menu.index(st.session_state.active_screen))
st.session_state.active_screen = user_choice

if st.session_state.error_count >= 3:
    st.session_state.active_screen = "Admin Login"
    st.warning("🔐 Access temporarily restricted due to multiple incorrect attempts.")

# -------------------------🏠 Dashboard Screen -------------------------

if st.session_state.active_screen == "Dashboard":
    st.subheader("🏠 Main Dashboard")
    st.markdown("Choose an action below:")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("➕ Save New Info", use_container_width=True):
            switch_screen("Save Info")
    with col2:
        if st.button("🔓 Access Info", use_container_width=True):
            switch_screen("Access Info")

    st.info(f"📦 Total entries stored securely: `{len(st.session_state.secure_store)}`")


# -------------------------💾 Save Info Screen -------------------------

elif st.session_state.active_screen == "Save Info":
    st.subheader("📝 Store Confidential Data")

    st.markdown("Provide the details below to encrypt and save your data safely.")

    user_input = st.text_area("🔐 Text to Secure:")
    passcode = st.text_input("🔑 Create Passcode:", type="password")
    passcode_confirm = st.text_input("🔁 Confirm Passcode:", type="password")

    if st.button("✅ Encrypt & Save"):
        if user_input and passcode and passcode_confirm:
            if passcode != passcode_confirm:
                st.error("⚠️ Passcodes don't match.")
            else:
                entry_id = create_unique_id()
                encrypted_text = lock_data(user_input, passcode)
                hashed_pass = create_hash(passcode)

                st.session_state.secure_store[entry_id] = {
                    "encrypted_text": encrypted_text,
                    "passcode": hashed_pass
                }

                st.success("🎉 Info encrypted and saved!")
                st.code(entry_id, language="text")
                st.markdown("✅ Save this Entry ID to retrieve your data in the future.")
        else:
            st.error("⚠️ All fields are required.")


# -------------------------🔍 Access Info Screen -------------------------

elif st.session_state.active_screen == "Access Info":
    st.subheader("🔍 Retrieve Your Encrypted Info")

    remaining = 3 - st.session_state.error_count
    st.info(f"⏳ Remaining Attempts: `{remaining}`")

    entry_id = st.text_input("🆔 Entry ID:")
    access_code = st.text_input("🔑 Passcode:", type="password")

    if st.button("🔓 Decrypt Info"):
        if entry_id and access_code:
            if entry_id in st.session_state.secure_store:
                encrypted_val = st.session_state.secure_store[entry_id]["encrypted_text"]
                result = unlock_data(encrypted_val, access_code, entry_id)

                if result:
                    st.success("🔓 Decryption Successful!")
                    st.markdown("#### 📄 Decrypted Info:")
                    st.code(result, language="text")
                else:
                    st.error(f"❌ Invalid passcode. Remaining attempts: {3 - st.session_state.error_count}")
            else:
                st.error("🚫 Entry ID not found.")

            if st.session_state.error_count >= 3:
                st.warning("🚨 Too many failed attempts. Redirecting to Admin Login...")
                st.rerun()
        else:
            st.error("⚠️ Please complete all fields.")


# -------------------------🛠️ Admin Login Screen -------------------------

elif st.session_state.active_screen == "Admin Login":
    st.subheader("🛡️ Admin Access Required")

    cooldown = 10
    time_remaining = cooldown - (time.time() - st.session_state.last_error_time)

    if time_remaining > 0 and st.session_state.error_count >= 3:
        st.warning(f"⏳ Please wait `{int(time_remaining)}` seconds before retrying.")
    else:
        master_pass = st.text_input("🔐 Admin Password:", type="password")
        if st.button("🔓 Verify"):
            if master_pass == "12345":  # Change this in production!
                clear_error_log()
                st.success("✅ Access Restored.")
                switch_screen("Dashboard")
                st.rerun()
            else:
                st.error("❌ Incorrect admin password.")


# -------------------------📌 Footer -------------------------

st.markdown("---")
st.markdown("""
#### 🔐 Secure Info Vault  
_Developed for educational and demonstration purposes._  
Built using **Streamlit**, **Fernet Encryption**, and **Python** 🐍
""")
