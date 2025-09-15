from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64


class RSAProcessor:
    """Клас для роботи з RSA-шифруванням та гібридним шифруванням (RSA + AES)."""

    def __init__(self, key_size: int=2048):
        """
        Ініціалізує RSAProcessor з вказаним розміром ключа.
        :param key_size: довжина RSA-ключа в бітах (за замовчуванням 2048)
        """
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.generate_keys()


    def generate_keys(self) -> None:
        """
        Генерує нову пару RSA-ключів (приватний + публічний).
        Викликається автоматично під час створення екземпляра класу.
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, # стандартне значення для RSA
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()


    def encrypt(self, text: str) -> Dict[str, Any]:
        """
        Шифрує текст за допомогою публічного ключа.
        :param text: вхідний рядок для шифрування
        :return: словник із зашифрованими даними:
                 - ciphertext_bytes: байтове представлення шифротексту
                 - ciphertext_b64: base64-подання для зручного друку/зберігання
        """
        ciphertext = self.public_key.encrypt(
            text.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), # маскування
                algorithm=hashes.SHA256(), # хеш-функція
                label=None
            )
        )
        return {
            "ciphertext_bytes": ciphertext,
            "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8")
        }


    def decrypt(self, ciphertext_bytes: bytes) -> str:
        """
        Розшифровує шифротекст за допомогою приватного ключа.
        :param ciphertext_bytes: байтовий рядок із зашифрованими даними
        :return: розшифрований текст (рядок)
        """
        decrypted = self.private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode("utf-8")


    def get_private_key_pem(self) -> str:
        """
        Повертає приватний ключ у форматі PEM (PKCS8, без шифрування).
        :return: PEM-рядок із приватним ключем
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8, # сучасний формат зберігання
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")


    def get_public_key_pem(self) -> str:
        """
        Повертає публічний ключ у форматі PEM (SubjectPublicKeyInfo).
        :return: PEM-рядок із публічним ключем
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")


if __name__ == "__main__":
    rsa_processor = RSAProcessor()

    # Вивід ключів у PEM-форматі
    print("Відкритий ключ:\n", rsa_processor.get_public_key_pem())
    print("Приватний ключ:\n", rsa_processor.get_private_key_pem())

    # Демонстрація шифрування та розшифрування короткого повідомлення
    original = "Тестове повідомлення RSA."

    enc_result = rsa_processor.encrypt(original)
    print("\nЗашифроване (base64):", enc_result["ciphertext_b64"])

    dec_result = rsa_processor.decrypt(enc_result["ciphertext_bytes"])
    print("\nРозшифроване повідомлення:", dec_result)
