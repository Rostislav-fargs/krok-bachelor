from typing import Optional


class CaesarCipher:
    """Клас для шифрування та розшифрування тексту за алгоритмом Цезаря."""

    def __init__(self, shift, alphabet: Optional[str] = None):
        """
        Ініціалізує об'єкт шифру Цезаря.

        :param shift: Кількість позицій для зсуву алфавіту.
        :type shift: int
        :param alphabet: Опціональний алфавіт, якщо None — використовується український.
        :type alphabet: Optional[str]
        """
        self.shift = shift
        default_alphabet = "абвгґдеєжзийіїйклмнопрстуфхцчшщьюя"
        self.alphabet = default_alphabet if alphabet is None else alphabet
        self.alphabet_size = len(self.alphabet)


    def encode_text(self, text: str) -> str:
        """
        Шифрує текст за алгоритмом Цезаря.

        :param text: Текст для шифрування.
        :type text: str
        :return: Зашифрований текст.
        :rtype: str
        """
        result = []
        for char in text:
            if char.lower() in self.alphabet:
                idx = self.alphabet.index(char.lower())
                new_idx = (idx + self.shift) % self.alphabet_size
                new_char = self.alphabet[new_idx]
                if char.isupper():
                    result.append(new_char.upper())
                else:
                    result.append(new_char) # символи поза алфавітом залишаються без змін
            else:
                result.append(char)
        return "".join(result)


    def decode_text(self, text: str) -> str:
        """
        Розшифровує текст, зашифрований алгоритмом Цезаря.

        :param text: Зашифрований текст.
        :type text: str
        :return: Розшифрований текст.
        :rtype: str
        """
        result = []
        for char in text:
            if char.lower() in self.alphabet:
                idx = self.alphabet.index(char.lower())
                new_idx = (idx - self.shift) % self.alphabet_size
                new_char = self.alphabet[new_idx]
                if char.isupper():
                    result.append(new_char.upper())
                else:
                    result.append(new_char) # символи поза алфавітом залишаються без змін
            else:
                result.append(char)
        return "".join(result)


if __name__ == "__main__":
    cesar_cipher = CaesarCipher(shift=14) # роботу виконано 14-го вересня

    with open("example.txt", "r", encoding="utf-8") as file:
        original = file.read()

    # Шифрування
    enc_result = cesar_cipher.encode_text(original)
    print(f"Зашифрований текст:\n {enc_result}")

    # Дешифрування
    dec_result = cesar_cipher.decode_text(enc_result)
    print(f"Розшифрований текст:\n {dec_result}")
