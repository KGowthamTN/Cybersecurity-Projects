import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QComboBox, QTextEdit, QMessageBox
from PyQt5.QtGui import QFont

class CaesarCipherApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Caesar Cipher Tool')
        self.setGeometry(100, 100, 600, 400)  # Increased size for better viewing

        font = QFont()
        font.setPointSize(14)  # Increased font size

        self.message_label = QLabel('Enter Message:')
        self.message_label.setFont(font)
        self.message_input = QLineEdit()
        self.message_input.setFont(font)

        self.shift_label = QLabel('Select Shift Value:')
        self.shift_label.setFont(font)
        self.shift_combo = QComboBox()
        self.shift_combo.setFont(font)
        self.shift_combo.addItems([str(i) for i in range(1, 26)])

        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.setFont(font)
        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.setFont(font)

        self.output_label = QLabel('Output:')
        self.output_label.setFont(font)
        self.output_display = QTextEdit()
        self.output_display.setFont(font)
        self.output_display.setReadOnly(True)

        self.encrypt_button.clicked.connect(self.encryptMessage)
        self.decrypt_button.clicked.connect(self.decryptMessage)

        layout = QVBoxLayout()
        layout.addWidget(self.message_label)
        layout.addWidget(self.message_input)
        layout.addWidget(self.shift_label)
        layout.addWidget(self.shift_combo)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        layout.addLayout(button_layout)

        layout.addWidget(self.output_label)
        layout.addWidget(self.output_display)

        self.setLayout(layout)

    def encryptMessage(self):
        plaintext = self.message_input.text()
        shift = int(self.shift_combo.currentText())
        encrypted_text = self.caesarCipher(plaintext, shift)
        self.output_display.setPlainText(encrypted_text)

    def decryptMessage(self):
        ciphertext = self.message_input.text()
        shift = int(self.shift_combo.currentText())
        decrypted_text = self.caesarCipher(ciphertext, -shift)  # Decrypt by shifting in the opposite direction
        self.output_display.setPlainText(decrypted_text)

    def caesarCipher(self, text, shift):
        result = ''
        for char in text:
            if char.isalpha():
                if char.islower():
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                else:
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                result += char
        return result

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CaesarCipherApp()
    window.show()
    sys.exit(app.exec_())
