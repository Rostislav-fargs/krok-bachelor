import base64
from typing import Dict, Optional, Any

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


class AESProcessor:
    """
    Клас для роботи з AES у різних режимах (ECB, CBC, CFB, OFB, CTR, GCM).
    Реалізує методи шифрування та дешифрування з використанням випадкового ключа.
    """

    def __init__(self):
        # Підтримувані режими шифрування
        self.support_modes = {
            "ECB": {"mode": AES.MODE_ECB},
            "CBC": {"mode": AES.MODE_CBC, "iv_len": 16},
            "CFB": {"mode": AES.MODE_CFB, "iv_len": 16},
            "OFB": {"mode": AES.MODE_OFB, "iv_len": 16},
            "CTR": {"mode": AES.MODE_CTR, "nonce_len": 8},
            "GCM": {"mode": AES.MODE_GCM, "nonce_len": 12},
        }
        # Генерування випадкового ключа AES (128 біт)
        self.key = get_random_bytes(16)


    def _get_module(self, mode_name: str) -> Dict[str, Any]:
        """Формує параметри для створення AES-об'єкта залежно від режиму."""
        mode_info = self.support_modes.get(mode_name.upper())

        if not mode_info:
            raise ValueError(f"Unsupported mode: {mode_name}")

        kwargs = {"mode": mode_info["mode"]}

        if "iv_len" in mode_info:
            kwargs["iv"] = get_random_bytes(mode_info["iv_len"]) # type: ignore
        if "nonce_len" in mode_info:
            kwargs["nonce"] = get_random_bytes(mode_info["nonce_len"]) # type: ignore

        return kwargs


    def _pad(self, data: Optional[bytes]=None) -> bytes:
        """Додає паддінг (PKCS7) для сумісності з блоковими режимами."""
        pad_len = 16 - len(data) % 16
        return data + bytes([pad_len]) * pad_len


    def _unpad(self, data: bytes) -> bytes:
        """Видаляє паддінг після розшифрування."""
        return data[:-data[-1]]


    def encrypt(self, mode_name: str, text: str) -> Dict[str, Any]:
        """
        Шифрує текст у вибраному режимі AES.
        :param mode_name: Назва режиму (ECB, CBC, CFB, OFB, CTR, GCM).
        :param text: Текст для шифрування.
        :return: Словник з шифротекстом і службовими параметрами (iv/nonce/tag).
        """
        kwargs = self._get_module(mode_name)
        cipher = AES.new(self.key, **kwargs)
        ciphertext = cipher.encrypt(self._pad(text.encode("utf-8")))

        if mode_name.upper() == "GCM": # Для GCM потрібен тег автентифікації
            return {"ciphertext": ciphertext, "nonce": kwargs["nonce"], "tag": cipher.digest()}

        return {"ciphertext": ciphertext, **{k: v for k, v in kwargs.items() if k in ("iv", "nonce", "mode")}}


    def decrypt(self, mode_name: str, ciphertext: bytes, **kwargs) -> str:
        """
        Дешифрує шифротекст у вихідний рядок.
        :param mode_name: Назва режиму.
        :param ciphertext: Шифротекст у байтах.
        :param kwargs: Службові параметри (iv, nonce, tag).
        :return: Розшифрований текст.
        """
        mode = self.support_modes[mode_name.upper()]["mode"]

        if mode_name.upper() == "GCM":
            cipher = AES.new(self.key, mode, nonce=kwargs["nonce"]) # type: ignore
            decrypted = cipher.decrypt_and_verify(ciphertext, kwargs["tag"])
        else:
            cipher_kwargs = {k: v for k, v in kwargs.items() if k in ("iv", "nonce")}
            cipher = AES.new(self.key, mode, **cipher_kwargs) # type: ignore
            decrypted = cipher.decrypt(ciphertext)

        return self._unpad(decrypted).decode("utf-8")


if __name__ == "__main__":
    with open("example.txt", "r", encoding="utf-8") as file:
        original = file.read()

    aes_processor = AESProcessor()

    modes = ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM"]

    # Демонстрація роботи режимів
    for mode in modes:
        print(f"\nРежим: {mode}")
        # Шифрування
        enc_result = aes_processor.encrypt(mode, original)
        print("Ciphertext (base64):", base64.b64encode(enc_result["ciphertext"]).decode())

        # Дешифрування
        dec_result = aes_processor.decrypt(mode, **enc_result)
        print("Decrypted text:", dec_result)

    # GCM шифрування та перевірка автентичності
    # Шифрування
    enc_result = aes_processor.encrypt("GCM", original)
    print("Ciphertext (base64):", base64.b64encode(enc_result["ciphertext"]).decode())
    print("Nonce:", enc_result["nonce"])
    print("Tag:", enc_result["tag"])

    # Дешифрування
    dec_result = aes_processor.decrypt("GCM", **enc_result)
    print("Decrypted text:", dec_result)

    # Перевірка зміни шифротексту
    try:
        enc_result["ciphertext"] =  enc_result["ciphertext"][1:] + b"\x00"  # модифікація
        aes_processor.decrypt("GCM", **enc_result)
    except ValueError:
        print("Decryption failed! Ciphertext or tag was modified.")
