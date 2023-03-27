from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.padding import PSS
from email.header import decode_header
from imaplib import IMAP4_SSL
import base64
import email
import os

from dotenv import load_dotenv
load_dotenv('../.env')

# Получаем письмо с файлом
def mail_with_file_get(_imap_server, _imap_username, _imap_password, _public_key_path):
    imap = IMAP4_SSL(_imap_server, 993)
    imap.login(_imap_username, _imap_password)
    imap.select('INBOX')
    typ, msg_ids = imap.search(None, 'ALL') # Ищем письма
    last_msg_id = msg_ids[0].split()[-1] # Получаем последнее письмо
    typ, msg_data = imap.fetch(last_msg_id, '(RFC822)')
    msg = email.message_from_bytes(msg_data[0][1])
    subject = decode_header(msg["Subject"])[0][0]
    sender = decode_header(msg["From"])[0][0]
    receiver = decode_header(msg["To"])[0][0]
    print(f"Тема письма: {subject}")
    print(f"От кого пришло: {sender}")
    print(f"Кому отправлено: {receiver}")
    msg_text = b''
    data = b''
    for part in msg.walk():
        # Отбираем только текстовые сообщения и прикрепленные файлы
        if part.get_content_type() == "text/plain":
            body = part.get_payload(decode=True)
            msg_text = body
        elif part.get_content_type() == "application/octet-stream":
            filename = decode_header(part.get_filename())[0][0]
            data = part.get_payload(decode=True)

            # Сохранить
            with open(filename, "wb") as f:
                f.write(data)
            print(f"Файл '{filename}' был сохранен!")

    # Расшифровываем текст сообщения
    msg_text = base64.b64decode(msg_text)

    # Закрываем IMAP подключение
    imap.close()
    imap.logout()

    return msg_text, data


# Проверка подписи
def signature_check(_signature, _file_data, _public_key_path):
    public_key_modal = public_key_check(_public_key_path)

    try:
        public_key_modal.verify(
            _signature,
            _file_data,
            padding=padding.PSS(padding.MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
            algorithm=hashes.SHA256()
        )
        print("Подпись подтверждена!")
        return True
    except InvalidSignature:
        print("Подпись не подтверждена!")
        return False

# Получение модели публичного ключа из файла
def public_key_check(key_path):
    with open(key_path, "rb") as key_file:
        public_key_modal = serialization.load_pem_public_key(key_file.read())
        return public_key_modal

if __name__ == '__main__':
    imap_server = os.getenv("imap_server")
    imap_username = os.getenv("imap_username")
    imap_password = os.getenv("imap_password")
    public_key_path = os.getenv("public_key_path")

    signature, file_data = mail_with_file_get(imap_server,imap_username,imap_password,public_key_path)

    signature_check(signature,file_data,public_key_path)
