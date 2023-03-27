from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import PSS
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import base64
import os
import smtplib as smtp

from dotenv import load_dotenv
load_dotenv('../.env')

# Создаем публичный и приватный ключ
def public_private_keys_create(_private_key_path, _public_key_path):
    _private_key_modal = private_key_create(_private_key_path)
    _public_key_modal = public_key_create(_private_key_modal, _public_key_path)

    return _private_key_modal, _public_key_modal

# Создаем приватный ключ и сохраняем необходимый файл
def private_key_create(_private_key_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(_private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return private_key

# Создаем публичный ключ в соответствии с приватным ключом и сохраняем необходимый файл
def public_key_create(_private_key_modal, _public_key_path):
    _public_key_modal = _private_key_modal.public_key()
    with open(_public_key_path, "wb") as f:
        f.write(_public_key_modal.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return _public_key_modal

# Создаем подпись
def signature_create(key_path, file_path, _signature_file_path):
    _private_key_modal = private_key_signature(key_path)

    with open(file_path, "rb") as file:
        file_data = file.read()

    _signature = _private_key_modal.sign(
        data=file_data,
        padding=padding.PSS(padding.MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
        algorithm=hashes.SHA256()
    )

    _signature = base64.b64encode(_signature)

    with open(_signature_file_path, "wb") as f:
        f.write(_signature)

    return _signature

# Получение модели приватного ключа из файла
def private_key_signature(key_path):
    with open(key_path, "rb") as key_file:
        _private_key_modal = serialization.load_pem_private_key(key_file.read(), password=None)
        return _private_key_modal

# Отправляем письмо вместе с файлом
def mail_with_file_send(_sender_email, _sender_password, _receiver_email, _subject, _attachment_path, _signature):
    message = MIMEMultipart()
    message["From"] = _sender_email
    message["To"] = _receiver_email
    message["Subject"] = _subject

    message.attach(MIMEText(_signature.decode("utf-8"), "plain"))

    with open(_attachment_path, "rb") as attachment:
        part = MIMEApplication(
            attachment.read(),
            Name=os.path.basename(_attachment_path)
        )
        part['Content-Disposition'] = f'attachment; filename="{os.path.basename(_attachment_path)}"'
        message.attach(part)

    with smtp.SMTP_SSL('smtp.yandex.com') as server:
        server.set_debuglevel(1)
        server.ehlo(_sender_email)
        server.login(_sender_email, _sender_password)
        server.auth_plain()
        server.sendmail(_sender_email, _receiver_email, message.as_string())
        print("Письмо было отправлено!")
        server.quit()

if __name__ == '__main__':
    private_key_path = os.getenv("private_key_path")
    public_key_path = os.getenv("public_key_path")
    letter_file_path = os.getenv("letter_file_path")
    signature_file_path = os.getenv("signature_file_path")

    sender_email = os.getenv("sender_email")
    sender_password = os.getenv("sender_password")
    receiver_email = os.getenv("receiver_email")
    subject = os.getenv("subject")

    private_key_modal, public_key_modal = public_private_keys_create(private_key_path, public_key_path)

    signature = signature_create(private_key_path, letter_file_path, signature_file_path)
    mail_with_file_send(sender_email,sender_password,receiver_email,subject,letter_file_path,signature)