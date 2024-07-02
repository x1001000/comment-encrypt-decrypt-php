import re
def contains_japanese(text):
    # This regex includes the Unicode ranges for Hiragana, Katakana, and CJK (which includes Kanji)
    japanese_regex = re.compile(r'[\u3040-\u30FF\u4E00-\u9FFF]')
    return bool(japanese_regex.search(text))


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Function to generate a key from a passphrase
def generate_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
# salt = b'some_salt'
# key = generate_key(passphrase, salt)
# print(f'加密解密金鑰: {key.decode()}')

def encrypt_comment(comment: str, key: bytes) -> str:
    fernet = Fernet(key)
    encrypted_comment = fernet.encrypt(comment.encode())
    return encrypted_comment.decode()

def encrypt_comments_in_file(file_content: str):
    # with open(file_path, 'r') as file:
    #     lines = file.readlines()
    lines = file_content.split('\n')

    encrypted_lines = []
    for line in lines:
        # if line.strip().startswith('#'):
        #     comment = line.strip()[1:].strip()
        #     encrypted_comment = encrypt_comment(comment, key)
        #     encrypted_lines.append(f"# {encrypted_comment}\n")
        try:
            space_or_code, comment = line.split('//')
        except:
            encrypted_lines.append(line)
        else:
            if contains_japanese(comment):
                encrypted_comment = encrypt_comment(comment, key)
                encrypted_lines.append(f'{space_or_code}//{encrypted_comment}')
            else:
                encrypted_lines.append(line)

    # with open(file_path, 'w') as file:
    #     file.writelines(encrypted_lines)
    return '\n'.join(encrypted_lines)

# # Usage
# file_path = 'your_source_code.cs'
# passphrase = 'your_secure_passphrase'
# encrypt_comments_in_file(file_path)

def decrypt_comment(encrypted_comment: str, key: bytes) -> str:
    fernet = Fernet(key)
    decrypted_comment = fernet.decrypt(encrypted_comment.encode())
    return decrypted_comment.decode()

def decrypt_comments_in_file(file_content: str):
    # with open(file_path, 'r') as file:
    #     lines = file.readlines()
    lines = file_content.split('\n')

    decrypted_lines = []
    for line in lines:
        # if line.strip().startswith('#'):
        #     encrypted_comment = line.strip()[1:].strip()
        #     try:
        #         decrypted_comment = decrypt_comment(encrypted_comment, key)
        #         decrypted_lines.append(f"# {decrypted_comment}\n")
        #     except Exception as e:
        #         decrypted_lines.append(line)
        try:
            space_or_code, comment = line.split('//')
        except:
            decrypted_lines.append(line)
        else:
            try:
                decrypted_comment = decrypt_comment(comment, key)
            except:
                decrypted_lines.append(line)
            else:
                decrypted_lines.append(f'{space_or_code}//{decrypted_comment}')

    # with open(file_path, 'w') as file:
    #     file.writelines(decrypted_lines)
    return '\n'.join(decrypted_lines)

# # Usage
# file_path = 'your_source_code.cs'
# passphrase = 'your_secure_passphrase'
# decrypt_comments_in_file(file_path)


import streamlit as st
st.title('C#腳本日文註解加密/解密工具')

passphrase = st.text_input("金鑰（自訂）")
salt = b'some_salt'
key = generate_key(passphrase, salt)

mode = st.selectbox("模式", ["加密", "解密"])

uploaded_file = st.file_uploader("上傳", type="cs")

import tempfile
if uploaded_file is not None and passphrase:
    file_content = uploaded_file.read().decode("utf-8")
    # with tempfile.NamedTemporaryFile(delete=False, suffix=".cs") as tmp_file:
    #     tmp_file.write(file_content.encode("utf-8"))
    #     tmp_file_path = tmp_file.name

    # processed_content = process_script(file_content, passphrase, salt, mode)
    if mode == "加密":
        processed_content = encrypt_comments_in_file(file_content)
    if mode == "解密":
        processed_content = decrypt_comments_in_file(file_content)
    
    st.download_button(
        label="下載",
        data=processed_content,
        file_name=uploaded_file.name,
        mime="text/x-python"
    )

    # st.text_area("Processed Script", value=processed_content, height=400)