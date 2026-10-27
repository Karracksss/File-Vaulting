import streamlit as st
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

st.set_page_config(page_title="Secure File Vaulting", page_icon="🔒", layout="centered")

st.title("🔒 Secure File Vaulting")
st.caption("Hybrid Cryptography: AES-256-GCM + RSA-OAEP")

tab1, tab2, tab3 = st.tabs(["🔑 Key Generation", "🔐 Encrypt File", "🔓 Decrypt File"])

# -------------------------------------------------------------------
# TAB 1: KEY GENERATION (Fixed with Session State)
# -------------------------------------------------------------------
with tab1:
    st.header("Generate RSA Key Pair")
    st.write("Generate a 3072-bit RSA public/private key pair.")

    if st.button("Generate RSA Keys"):
        # 1. Generate Key Pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )
        public_key = private_key.public_key()

        # 2. Serialize to PEM format and store in Session State
        st.session_state['pem_private'] = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        st.session_state['pem_public'] = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.session_state['keys_generated'] = True
        st.success("Keys generated and saved in memory!")

    # Display download buttons if keys exist in session state
    if st.session_state.get('keys_generated', False):
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="Download Public Key (.pem)",
                data=st.session_state['pem_public'],
                file_name="public_key.pem",
                mime="application/x-pem-file",
                key="download_pub"
            )
        with col2:
            st.download_button(
                label="Download Private Key (.pem)",
                data=st.session_state['pem_private'],
                file_name="private_key.pem",
                mime="application/x-pem-file",
                key="download_priv"
            )
# -------------------------------------------------------------------
# TAB 2: ENCRYPT FILE
# -------------------------------------------------------------------
with tab2:
    st.header("Encrypt File into .vault Package")
    uploaded_file = st.file_uploader("Select File to Encrypt")
    public_key_file = st.file_uploader("Upload Recipient's Public Key (.pem)", type=["pem"])

    if st.button("Encrypt & Vault File"):
        if uploaded_file and public_key_file:
            file_bytes = uploaded_file.read()
            filename = uploaded_file.name

            # Load Public Key
            public_key = serialization.load_pem_public_key(public_key_file.read())

            # 1. Generate AES-256 Key & Nonce
            aes_key = AESGCM.generate_key(bit_length=256)
            nonce = os.urandom(12)  # 96-bit nonce

            # 2. AES-GCM Encryption (with Filename as AAD)
            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(nonce, file_bytes, filename.encode('utf-8'))

            # 3. RSA-OAEP Encrypt the AES Key
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 4. Package into JSON Vault Format
            vault_package = {
                "format": "GUPIT-VAULT-V1",
                "filename": filename,
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "encrypted_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }

            vault_bytes = json.dumps(vault_package, indent=2).encode('utf-8')

            st.success("File Encrypted Successfully!")
            st.download_button("Download .vault Package", vault_bytes, f"{filename}.vault", "application/json")
        else:
            st.error("Please provide both a file and a public key.")

# -------------------------------------------------------------------
# TAB 3: DECRYPT FILE
# -------------------------------------------------------------------
with tab3:
    st.header("Decrypt .vault Package")
    vault_file = st.file_uploader("Upload .vault Package", type=["vault", "json"])
    private_key_file = st.file_uploader("Upload Private Key (.pem)", type=["pem"])

    if st.button("Decrypt Vault"):
        if vault_file and private_key_file:
            try:
                vault_data = json.load(vault_file)

                # Decode JSON base64 fields
                nonce = base64.b64decode(vault_data["nonce"])
                encrypted_aes_key = base64.b64decode(vault_data["encrypted_key"])
                ciphertext = base64.b64decode(vault_data["ciphertext"])
                filename = vault_data["filename"]

                # Load Private Key
                private_key = serialization.load_pem_private_key(
                    private_key_file.read(),
                    password=None
                )

                # 1. Recover AES Key using RSA Private Key
                aes_key = private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # 2. Decrypt & Verify Ciphertext using AES-GCM
                aesgcm = AESGCM(aes_key)
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, filename.encode('utf-8'))

                st.success("Authentication & Decryption Successful!")
                st.download_button(f"Download Decrypted {filename}", decrypted_bytes, filename)

            except Exception as e:
                st.error("Decryption / Authentication Failed! (Invalid Key or Tampered File)")
        else:
            st.error("Please upload both the .vault file and your private key.")