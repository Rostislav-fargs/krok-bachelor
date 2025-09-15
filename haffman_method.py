from collections import Counter
from typing import Dict, List, Optional


class Node:
    """
    Вузол для дерева Хаффмана.
    Зберігає символ, його частоту та посилання на дочірні вузли.
    """
    def __init__(
        self, char: Optional[str]=None,
        frequency: int=0,
        left: Optional['Node']=None,
        right: Optional['Node']=None
    ):
        self.char = char
        self.frequency = frequency
        self.left = left
        self.right = right


class HuffmanMethod:
    """Клас для створення дерева Хаффмана та кодування/декодування тексту."""

    def __init__(self, nodes: List[Node]):
        self.base_nodes = nodes # Вхідний список вузлів
        self._create_root_of_tree() # Побудова дерева
        self._generate_codes(self.root) # Генерація кодів для кожного символа

    def _create_root_of_tree(self):
        """Будує дерево Хаффмана з вхідного списку вузлів."""
        copy_nodes = self.base_nodes.copy()

        # Ітерування по вузлах (по вхідних та створених у процесі)
        while len(copy_nodes) > 1:
            copy_nodes.sort(key=lambda node: node.frequency) # Сортування за частотою

            # Отримання вузлів із найменшою частотою
            left_p = copy_nodes.pop(0)
            right_p = copy_nodes.pop(0)

            # Створення нового вузла за сумою частот обраних лівого та правого
            new_node = Node(
                char=None,
                frequency=left_p.frequency + right_p.frequency,
                left=left_p,
                right=right_p
            )

            # Додавання нового вузла у список
            copy_nodes.append(new_node)

        # Ініціалізація кореню дерева
        self.root = copy_nodes[0]


    def _generate_codes(
        self, node: Node,
        prefix: str="",
        code_dict: Optional[Dict[str, str]]=None
    ):
        """Рекурсивна гереація кодів для кожного символа з листових вузлів."""
        if code_dict is None:
            code_dict = {}

        if node.char is not None: # Якщо вузол має символ, то він листовий
            code_dict[node.char] = prefix
        else:
            # Рекурсивних обіхд правого та лівого вузла, якщо вузол не листовий
            self._generate_codes(node.left, prefix + "0", code_dict)
            self._generate_codes(node.right, prefix + "1", code_dict)

        # Ініціалізація кодів для символів
        self.code_dict = code_dict


    def encode_text(self, text: str) -> str:
        """Кодує тексту у бітовий рядок."""
        char_list = []
        for char in text:
            char_code = self.code_dict.get(char)
            if char_code is not None:
                char_list.append(char_code)

        return "".join(char_list)


    def decode_text(self, encoded_text: str) -> str:
        """Декодує текст з бітового рядка за допомогою дерева."""
        result = []
        temp_node = self.root

        for bit in encoded_text:
            # Залежно від біта перехід до правого або лівого вузла
            temp_node = temp_node.left if bit == "0" else temp_node.right

            # Якщо вузол має символ, то він листовий
            if temp_node.char is not None:
                result.append(temp_node.char) # Додавання символу
                temp_node = self.root

        return "".join(result)


class HuffmanBasedProcessor:
    """Обробник тексту на базі алгоритму Хаффмана."""

    def __init__(self, text: str):
        self.base_text = text
        self._create_huffman_tree()
        self.huffman = HuffmanMethod(self.nodes)


    def _count_chars_freq(self):
        """Обраховує частоти символів у тексті."""
        return Counter(self.base_text)


    def _create_huffman_tree(self):
        """Створює вузли з символів у тексті."""
        freq_dict = self._count_chars_freq()
        self.nodes = []
        for char, freq in freq_dict.items():
            self.nodes.append(Node(char, freq))


    def encode_text(self, text: Optional[str]=None) -> str:
        """
        Кодує текст.

        Якщо не було передано тексту для кодування, то використовує текст, наданий під час ініцалізації об'єкту класа.
        """
        if text is None:
            text = self.base_text

        return self.huffman.encode_text(text)


    def decode_text(self, text: str) -> str:
        """Декодує текст."""
        return self.huffman.decode_text(text)


if __name__ == "__main__":
    with open("example.txt", "r", encoding="utf-8") as file:
        original = file.read()

    # Ініціалізація обробника тексту
    huffman = HuffmanBasedProcessor(original)

    # Кодування наданого тексту
    enc_result = huffman.encode_text()
    print(enc_result)

    # Декодування закодованого тексту
    dec_result = huffman.decode_text(enc_result)
    print(dec_result)
