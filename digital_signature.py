import base64

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from rsa_processor import RSAProcessor


class DigitalSignatureWithRSAProcessor:
    """
    Клас для створення та перевірки електронного цифрового підпису (ЕЦП) з використанням RSA.

    Використовує RSAProcessor для доступу до ключів.
    """

    def __init__(self, rsa_processor: RSAProcessor):
        """
        Ініціалізує DigitalSignatureWithRSAProcessor.

        :param rsa_processor: Об'єкт RSAProcessor, який містить пару ключів (приватний та публічний).
        :type rsa_processor: RSAProcessor
        """
        self.rsa = rsa_processor


    def sign_text(self, text: str) -> str:
        """
        Створює цифровий підпис для повідомлення.

        :param text: Текст повідомлення для підпису.
        :type text: str
        :return: Підпис у форматі Base64.
        :rtype: str
        """
        signature = self.rsa.private_key.sign(
            text.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("utf-8")


    def verify_text(self, message: str, signature_b64: str) -> bool:
        """
        Перевіряє цифровий підпис повідомлення.

        :param message: Текст повідомлення для перевірки.
        :type message: str
        :param signature_b64: Підпис повідомлення у форматі Base64.
        :type signature_b64: str
        :return: True, якщо підпис дійсний, False — якщо ні.
        :rtype: bool
        """
        signature = base64.b64decode(signature_b64)
        try:
            self.rsa.public_key.verify(
                signature,
                message.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


if __name__ == "__main__":
    rsa_proc = RSAProcessor()

    with open("example.txt", "r", encoding="utf-8") as file:
        original = file.read()

    ds = DigitalSignatureWithRSAProcessor(rsa_proc)

    # Шифрування
    sig = ds.sign_text(original)
    print("Підпис:", sig)

    # Розшифрування
    print("Валідація:", ds.verify_text(original, sig))
    print("Валідація зміненого:", ds.verify_text(original + "X", sig))
