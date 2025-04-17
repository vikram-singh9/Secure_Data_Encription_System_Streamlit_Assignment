
import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate key (you can replace this with a hardcoded key if you want persistence)
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

cipher = Fernet(st.session_state.fernet_key)

# Initialize in-memory data and attempts
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Helper Functions ---

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_text(plain_text: str) -> str:
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_text(encrypted_text: str) -> str:
    return cipher.decrypt(encrypted_text.encode()).decode()

def reset_attempts():
    st.session_state.failed_attempts = 0

# --- Streamlit App ---

st.set_page_config(page_title="Secure Data Vault", layout="centered")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📂 Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.markdown("This app allows you to **securely store and retrieve data** using your secret passkey.")
    st.markdown("Data is encrypted using `Fernet` symmetric encryption and passkey is hashed for safety.")
    st.info("🔒 All data is stored in memory. Closing the app will clear it.")

elif choice == "Store Data":
    st.subheader("📥 Store Your Secret")
    label = st.text_input("Enter a Label (e.g., Note1, Password, etc.)")
    user_text = st.text_area("Enter the Data You Want to Encrypt:")
    passkey = st.text_input("Set a Passkey to Protect Your Data:", type="password")

    if st.button("Encrypt and Store"):
        if label and user_text and passkey:
            hashed_key = hash_passkey(passkey)
            encrypted_text = encrypt_text(user_text)
            st.session_state.stored_data[label] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_key
            }
            st.success(f"✅ Your data under label '{label}' has been securely stored.")
        else:
            st.error("⚠️ Please fill in all fields.")

elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Your Secret")
    
    if st.session_state.failed_attempts >= 3:
        st.warning("🚫 Too many failed attempts. Please reauthorize from the Login page.")
        st.stop()

    label = st.text_input("Enter the Label You Used:")
    passkey = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Decrypt and Show"):
        if label in st.session_state.stored_data:
            stored = st.session_state.stored_data[label]
            if hash_passkey(passkey) == stored["passkey"]:
                decrypted = decrypt_text(stored["encrypted_text"])
                st.success(f"🔓 Decrypted Data: {decrypted}")
                reset_attempts()
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
        else:
            st.error("❗ No data found under this label.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    master_pass = st.text_input("Enter Master Password to Reset Attempts:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            reset_attempts()
            st.success("✅ Access restored. You can now retry decryption.")
        else:
            st.error("❌ Incorrect master password!")
