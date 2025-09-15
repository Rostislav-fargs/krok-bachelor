import json
import os
import base64

from aes_processor import AESProcessor
from rsa_processor import RSAProcessor


class FileEncryptor:
    """
    Клас для гібридного шифрування файлів.
    - Контент файлу шифрується AES (симетричне шифрування).
    - AES-ключ додатково шифрується RSA (асиметричне шифрування).
    """

    def __init__(self):
        """Ініціалізує AES і RSA обробники."""
        self.aes = AESProcessor()
        self.rsa = RSAProcessor()


    def encrypt_file(self, input_path: str, output_file: str, key_file: str) -> None:
        """
        Шифрує файл за допомогою AES та RSA і зберігає результати на диск.

        Дії методу:
        1. Читає файл за шляхом input_path.
        2. Шифрує вміст AES (режим CBC).
        3. Шифрує AES-ключ за допомогою RSA.
        4. Зберігає зашифрований контент і IV у output_file (JSON).
        5. Зберігає зашифрований AES-ключ у key_file (Base64).

        :param input_path: Шлях до файлу, який потрібно зашифрувати.
        :type input_path: str
        :param output_file: Шлях до вихідного зашифрованого файлу.
        :type output_file: str
        :param key_file: Шлях до файлу, у який буде записаний зашифрований AES-ключ.
        :type key_file: str
        :raises FileNotFoundError: якщо файл input_path не знайдено.
        :return: None
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"{input_path} not defined.")

        # Читання вмісту файлу
        with open(input_path, "rb") as f:
            plaintext = f.read()

        # Шифрування контенту AES (CBC)
        aes_encrypted = self.aes.encrypt("CBC", plaintext.decode("utf-8"))

        # Зашифрувати AES ключ через RSA
        aes_key_encrypted = self.rsa.encrypt(base64.b64encode(self.aes.key).decode("utf-8"))

        # Збереження зашифрованого контенту + IV
        with open(output_file, "w", encoding="utf-8") as f:
            data_to_save = {
                "ciphertext": base64.b64encode(aes_encrypted["ciphertext"]).decode("utf-8"),
                "iv": base64.b64encode(aes_encrypted["iv"]).decode("utf-8")  # зберігаємо IV
            }
            f.write(json.dumps(data_to_save))

        # Збереження зашифрованого AES-ключа
        with open(key_file, "w", encoding="utf-8") as f:
            f.write(aes_key_encrypted["ciphertext_b64"])

        print(f"Файл зашифровано: {output_file}")
        print(f"AES ключ зашифровано: {key_file}")


    def decrypt_file(self, encrypted_file: str, key_file: str, output_path: str) -> None:
        """
        Розшифровує зашифрований файл і зберігає результат на диск.

        Дії методу:
        1. Зчитує зашифрований AES-ключ із key_file та розшифровує RSA.
        2. Встановлює розшифрований AES-ключ у AESProcessor.
        3. Зчитує зашифрований файл (ciphertext + IV) із encrypted_file.
        4. Розшифровує файл AES.
        5. Записує розшифрований контент у output_path.

        :param encrypted_file: Шлях до зашифрованого файлу.
        :type encrypted_file: str
        :param key_file: Шлях до файлу з зашифрованим AES-ключем.
        :type key_file: str
        :param output_path: Шлях до файлу, куди буде записаний розшифрований контент.
        :type output_path: str
        :return: None
        """
        # Зчитування зашифрованого AES-ключа
        with open(key_file, "r", encoding="utf-8") as f:
            aes_key_b64_encrypted = f.read()

        aes_key_bytes_encrypted = base64.b64decode(aes_key_b64_encrypted)
        aes_key_b64 = self.rsa.decrypt(aes_key_bytes_encrypted)
        aes_key = base64.b64decode(aes_key_b64)

        # Встановлюємо AES-ключ
        self.aes.key = aes_key

        # Зчитування зашифрованого файлу
        with open(encrypted_file, "r", encoding="utf-8") as f:
            saved_data = json.loads(f.read())
            ciphertext_bytes = base64.b64decode(saved_data["ciphertext"])
            iv_bytes = base64.b64decode(saved_data["iv"])

        # Розшифрування AES
        plaintext = self.aes.decrypt("CBC", ciphertext_bytes, iv=iv_bytes)

        # Запис на диск
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(plaintext)

        print(f"Файл розшифровано: {output_path}")


if __name__ == "__main__":
    fe = FileEncryptor()

    # Шифрування
    fe.encrypt_file("example.txt", "example_encrypted.txt", "aes_key_encrypted.txt")

    # Розшифрування
    fe.decrypt_file("example_encrypted.txt", "aes_key_encrypted.txt", "example_decrypted.txt")
