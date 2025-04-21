import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid

# Initialize session state variables
if 'error_count' not in st.session_state:
    st.session_state.error_count = 0
if 'secure_store' not in st.session_state:
    st.session_state.secure_store = {}
if 'active_screen' not in st.session_state:
    st.session_state.active_screen = "Dashboard"
if 'last_error_time' not in st.session_state:
    st.session_state.last_error_time = 0

# Hashing function for passcodes
def create_hash(passcode):
    return hashlib.sha256(passcode.encode()).hexdigest()

# Key derivation for Fernet
def derive_key(passcode):
    hashed = hashlib.sha256(passcode.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Encryption process
def lock_data(plain_text, passcode):
    key = derive_key(passcode)
    cipher = Fernet(key)
    return cipher.encrypt(plain_text.encode()).decode()

# Decryption process
def unlock_data(cipher_text, passcode, key_id):
    try:
        hashed_key = create_hash(passcode)
        if key_id in st.session_state.secure_store and st.session_state.secure_store[key_id]["passcode"] == hashed_key:
            key = derive_key(passcode)
            cipher = Fernet(key)
            output = cipher.decrypt(cipher_text.encode()).decode()
            st.session_state.error_count = 0
            return output
        else:
            st.session_state.error_count += 1
            st.session_state.last_error_time = time.time()
            return None
    except:
        st.session_state.error_count += 1
        st.session_state.last_error_time = time.time()
        return None

# Unique ID generator
def create_unique_id():
    return str(uuid.uuid4())

# Reset function
def clear_error_log():
    st.session_state.error_count = 0

# Page switcher
def switch_screen(screen):
    st.session_state.active_screen = screen

# ------------------- Streamlit App UI -------------------

st.title("🔐 Secure Data Vault")

menu = ["Dashboard", "Save Info", "Access Info", "Admin Login"]
user_choice = st.sidebar.selectbox("Navigate", menu, index=menu.index(st.session_state.active_screen))
st.session_state.active_screen = user_choice

# Lock after 3 failed attempts
if st.session_state.error_count >= 3:
    st.session_state.active_screen = "Admin Login"
    st.warning("🔒 Access blocked due to multiple failures.")

# Home page
if st.session_state.active_screen == "Dashboard":
    st.subheader("🏠 Welcome to Your Encrypted Vault")
    st.write("Protect and retrieve sensitive information using private passcodes.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("➕ Save New Info", use_container_width=True):
            switch_screen("Save Info")
    with col2:
        if st.button("🔓 Access Info", use_container_width=True):
            switch_screen("Access Info")
    
    st.info(f"🗂 Total secured entries: {len(st.session_state.secure_store)}")

# Store data page
elif st.session_state.active_screen == "Save Info":
    st.subheader("📝 Save Confidential Info")
    user_input = st.text_area("Enter Text to Secure:")
    passcode = st.text_input("Create Passcode:", type="password")
    passcode_confirm = st.text_input("Confirm Passcode:", type="password")

    if st.button("Encrypt & Store"):
        if user_input and passcode and passcode_confirm:
            if passcode != passcode_confirm:
                st.error("❌ Passcodes do not match!")
            else:
                entry_id = create_unique_id()
                hashed_pass = create_hash(passcode)
                encrypted_entry = lock_data(user_input, passcode)

                st.session_state.secure_store[entry_id] = {
                    "encrypted_text": encrypted_entry,
                    "passcode": hashed_pass
                }

                st.success("✅ Info secured successfully!")
                st.code(entry_id, language="text")
                st.info("🔑 Save your Entry ID to retrieve this later.")
        else:
            st.error("⚠️ Please fill out all fields.")

# Retrieve data page
elif st.session_state.active_screen == "Access Info":
    st.subheader("🔎 Access Encrypted Info")
    remaining_tries = 3 - st.session_state.error_count
    st.info(f"Attempts left: {remaining_tries}")

    entry_id = st.text_input("Enter Entry ID:")
    access_code = st.text_input("Enter Passcode:", type="password")

    if st.button("Decrypt"):
        if entry_id and access_code:
            if entry_id in st.session_state.secure_store:
                encrypted_val = st.session_state.secure_store[entry_id]["encrypted_text"]
                decrypted_val = unlock_data(encrypted_val, access_code, entry_id)

                if decrypted_val:
                    st.success("🔓 Info Decrypted!")
                    st.markdown("#### Your Info:")
                    st.code(decrypted_val, language="text")
                else:
                    st.error(f"❌ Invalid passcode! Remaining attempts: {3 - st.session_state.error_count}")
            else:
                st.error("🚫 Entry ID not recognized.")

            if st.session_state.error_count >= 3:
                st.warning("🚨 Maximum attempts reached. Redirecting to login.")
                st.session_state.active_screen = "Admin Login"
                st.rerun()
        else:
            st.error("⚠️ Both fields must be filled.")

# Login after lockout
elif st.session_state.active_screen == "Admin Login":
    st.subheader("🔐 Admin Verification")

    if time.time() - st.session_state.last_error_time < 10 and st.session_state.error_count >= 3:
        wait_time = int(10 - (time.time() - st.session_state.last_error_time))
        st.warning(f"⏳ Wait {wait_time} seconds before retrying.")
    else:
        master_key = st.text_input("Enter Admin Password:", type="password")
        if st.button("Verify"):
            if master_key == "admin12345":  # Modify this in production!
                clear_error_log()
                st.success("✅ Access Restored.")
                st.session_state.active_screen = "Dashboard"
                st.rerun()
            else:
                st.error("❌ Incorrect admin password.")

# Footer
st.markdown("---")
st.markdown("🔐 Secure Vault Project | Educational Use | Modified by You 😎")
