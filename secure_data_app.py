import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ---------------------- STREAMLIT CONFIG ----------------------
st.set_page_config(page_title="🔐 Secure Data Vault", layout="centered")

# ---------------------- SESSION STATE ----------------------
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False

# ---------------------- DARK THEME STYLE ----------------------
st.markdown("""
<style>
/* background colors here ... */

html, body, [class*="css"] {
    background-color: #0a0f2c !important;
    color: #ffffff !important;
}

/* Sidebar bg */
section[data-testid="stSidebar"] {
    background-color: #0d1436 !important;
}

/* Titles */
.title {
    font-size: 2.4em;
    font-weight: bold;
    text-align: center;
    color: #2f80ed;
    margin-top: 20px;
}

.subtitle, .stMarkdown p {
    color: #cfd8ff !important;
}

.box, .highlight-box {
    background-color: #121c4a;
    padding: 25px;
    border-radius: 15px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.6);
    border-left: 4px solid #2f80ed;
    margin-top: 20px;
    color: #ffffff !important;
}

.stTextInput>div>div>input,
.stTextArea>div>textarea,
.stPasswordInput>div>div>input {
    background-color: #1e2a63 !important;
    color: #e1e4f0 !important;
    border: 1px solid #3a4b85 !important;
    border-radius: 6px;
}

.stButton>button {
    background-color: #2f80ed !important;
    color: #ffffff !important;
    border-radius: 6px;
    padding: 0.5rem 1.2rem;
    transition: background 0.3s ease;
}

.stButton>button:hover {
    background-color: #1f60c4 !important;
}
</style>
""", unsafe_allow_html=True)


# ---------------------- ENCRYPTION FUNCTIONS ----------------------
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    record = st.session_state.stored_data.get(encrypted_text)
    if record and record["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# ---------------------- HEADER ----------------------
st.markdown('<div class="title">🔐 Secure Data Encryption System</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Encrypt, store, and retrieve data securely using passkeys</div>', unsafe_allow_html=True)
st.markdown("---")

# ---------------------- NAVIGATION ----------------------
menu = ["🏠 Home", "📥 Store Data", "🔍 Retrieve Data", "🔑 Login"]
choice = st.sidebar.selectbox("📂 Menu", menu)

# ---------------------- HOME ----------------------
if choice == "🏠 Home":
    st.markdown('<div class="box">', unsafe_allow_html=True)
    st.subheader("Welcome to your private vault 🏠")
    st.write("""
    - 🔐 Encrypt and store data with a secure passkey  
    - 🔓 Retrieve only with correct passkey  
    - ❌ 3 failed attempts lock access  
    - 🚫 All data stays in memory — no external storage used
    """)
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------------- STORE DATA ----------------------
elif choice == "📥 Store Data":
    st.markdown('<div class="box">', unsafe_allow_html=True)
    st.subheader("📥 Encrypt and Store")
    user_data = st.text_area("📝 Enter data to encrypt:")
    passkey = st.text_input("🔑 Choose a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and saved!")
            st.code(encrypted, language="text")
        else:
            st.warning("⚠️ Please fill in both fields.")
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------------- RETRIEVE DATA ----------------------
elif choice == "🔍 Retrieve Data":
    if st.session_state.failed_attempts >= 3:
        st.warning("🚫 Access locked. Please login.")
        st.stop()

    st.markdown('<div class="box">', unsafe_allow_html=True)
    st.subheader("🔍 Retrieve and Decrypt")
    encrypted_input = st.text_area("🔐 Paste encrypted data:")
    passkey = st.text_input("🔑 Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Decryption successful!")
                st.code(result, language="text")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. {remaining} attempts left.")
        else:
            st.warning("⚠️ Enter both encrypted text and passkey.")
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------------- LOGIN PAGE ----------------------
elif choice == "🔑 Login":
    st.markdown('<div class="box">', unsafe_allow_html=True)
    st.subheader("🔐 Admin Reauthorization")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized. Try retrieving data again.")
        else:
            st.error("❌ Invalid password.")
    st.markdown('</div>', unsafe_allow_html=True)
