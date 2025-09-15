from typing import Optional


class VigenereCipher:
    """Клас для шифрування та розшифрування тексту за алгоритмом Віженера."""

    def __init__(self, key: str, alphabet: Optional[str]=None):
        """
        Ініціалізує об'єкт шифру Віженера.

        :param key: Ключ шифрування, використовується для зсуву літер.
        :type key: str
        :param alphabet: Опціональний алфавіт, якщо None — використовується український.
        :type alphabet: Optional[str]
        """
        default_alphabet = "абвгґдеєжзийіїйклмнопрстуфхцчшщьюя"
        self.alphabet = default_alphabet if alphabet is None else alphabet
        self.key = key.lower()
        self.alphabet_size = len(self.alphabet)


    def _shift(self, char: str, key_char: str, encode: bool=True) -> str:
        """
        Зсуває символ char на позицію, визначену символом ключа key_char.

        :param char: Символ тексту для шифрування/розшифрування.
        :type char: str
        :param key_char: Символ ключа, який визначає зсув.
        :type key_char: str
        :param encode: True для шифрування, False для розшифрування.
        :type encode: bool
        :return: Зсунутий символ з урахуванням регістру.
        :rtype: str
        """
        if char.lower() not in self.alphabet:
            return char

        char_idx = self.alphabet.index(char.lower())
        key_idx = self.alphabet.index(key_char.lower())

        if encode:
            new_idx = (char_idx + key_idx) % self.alphabet_size
        else:
            new_idx = (char_idx - key_idx) % self.alphabet_size

        new_char = self.alphabet[new_idx]
        return new_char.upper() if char.isupper() else new_char


    def encode_text(self, text: str) -> str:
        """
        Шифрує текст за допомогою ключа Віженера.

        :param text: Текст для шифрування.
        :type text: str
        :return: Зашифрований текст.
        :rtype: str
        """
        result = []
        key_index = 0
        for char in text:
            key_char = self.key[key_index % len(self.key)]
            result.append(self._shift(char, key_char, encode=True))
            if char.lower() in self.alphabet:
                key_index += 1
        return "".join(result)


    def decode_text(self, text: str) -> str:
        """
        Розшифровує текст, зашифрований алгоритмом Віженера.

        :param text: Зашифрований текст.
        :type text: str
        :return: Розшифрований текст.
        :rtype: str
        """
        result = []
        key_index = 0
        for char in text:
            key_char = self.key[key_index % len(self.key)]
            result.append(self._shift(char, key_char, encode=False))
            if char.lower() in self.alphabet:
                key_index += 1
        return "".join(result)


if __name__ == "__main__":
    cipher = VigenereCipher(key="Шевченко")

    with open("example.txt", "r", encoding="utf-8") as file:
        original = file.read()

    # Шифрування
    enc_result = cipher.encode_text(original)
    print("Закодовано:\n", enc_result)

    # Дешифрування
    dec_result = cipher.decode_text(enc_result)
    print("Розкодовано:\n", dec_result)
