import re
import base64
import hashlib
from cryptography.fernet import Fernet
import streamlit as st
from zipfile import ZipFile
from io import BytesIO

def contains_japanese(text):
    # This regex includes the Unicode ranges for Hiragana, Katakana, and CJK (which includes Kanji)
    japanese_regex = re.compile(r'[\u3040-\u30FF\u4E00-\u9FFF]')
    return bool(japanese_regex.search(text))

# Function to generate a key from a passphrase
def generate_key(passphrase: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(passphrase.encode()).digest())

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
        match = re.search('|'.join(['//', '#region ', '#endregion ']), line, re.IGNORECASE)
        if match:
            space_or_code, comment = line.split(match.group(0), 1)
            if contains_japanese(comment):
                encrypted_comment = encrypt_comment(comment, key)
                encrypted_lines.append(f'{space_or_code}{match.group(0)}{encrypted_comment}')
            else:
                encrypted_lines.append(line)
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
        match = re.search('|'.join(['//', '#region ', '#endregion ']), line, re.IGNORECASE)
        if match:
            space_or_code, comment = line.split(match.group(0), 1)
            try:
                decrypted_comment = decrypt_comment(comment, key)
                decrypted_lines.append(f'{space_or_code}{match.group(0)}{decrypted_comment}')
            except:
                decrypted_lines.append(line)
        else:
            decrypted_lines.append(line)

    # with open(file_path, 'w') as file:
    #     file.writelines(decrypted_lines)
    return '\n'.join(decrypted_lines)

# # Usage
# file_path = 'your_source_code.cs'
# passphrase = 'your_secure_passphrase'
# decrypt_comments_in_file(file_path)


st.title('C#腳本日文註解加密/解密工具')

passphrase = st.text_input("金鑰（自訂）")
key = generate_key(passphrase)

process = {'加密': encrypt_comments_in_file, '解密': decrypt_comments_in_file}
mode = st.selectbox('模式', process.keys())

uploaded_file = st.file_uploader("上傳", type=['cs', 'zip'])

if uploaded_file is not None and passphrase:
    file_name, ext = uploaded_file.name.split('.')
    if ext.lower() == 'cs':
        file_name = f'{file_name}.cs'
        mime_type = 'text/plain'
        file_content = uploaded_file.read().decode()
        download = processed_content = process[mode](file_content)
    if ext.lower() == 'zip':
        file_name = f'{file_name}_{mode}.zip'
        mime_type = 'application/zip'

        target_zip_buffer = BytesIO()
        with ZipFile(target_zip_buffer, 'w') as target_zip:
            with ZipFile(uploaded_file, 'r') as source_zip:
                for name in source_zip.namelist():
                    with source_zip.open(name) as file:
                        try:
                            file_content = file.read().decode()
                            if name.endswith('.cs'):
                                processed_content = process[mode](file_content)
                                target_zip.writestr(name, processed_content)
                            else:
                                target_zip.writestr(name, file_content)
                        except:
                            pass
        target_zip_buffer.seek(0)
        download = target_zip_buffer

    # processed_content = process_script(file_content, passphrase, salt, mode)
    # st.text_area("Processed Script", value=processed_content, height=400)
    st.download_button(
        label="下載",
        data=download,
        file_name=file_name,
        mime=mime_type
    )