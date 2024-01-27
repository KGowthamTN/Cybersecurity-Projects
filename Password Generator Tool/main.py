import sys
import random
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt


def show_error_message(title, message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.exec_()


def show_message(title, message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.exec_()


class PasswordGenerator(QWidget):
    def __init__(self):
        super().__init__()

        self.numbers_label = None
        self.copy_button = None
        self.generated_password = None
        self.password_label = None
        self.special_input = None
        self.generate_button = None
        self.special_label = None
        self.length_input = None
        self.numbers_input = None
        self.lowercase_input = None
        self.capitalized_input = None
        self.lowercase_label = None
        self.capitalized_label = None
        self.length_label = None
        self.init_ui()

    def init_ui(self):
        self.length_label = QLabel('Length:')
        self.length_input = QLineEdit()
        self.length_input.setPlaceholderText('Enter length')
        self.length_input.setText('14')

        self.capitalized_label = QLabel('Capitalized:')
        self.capitalized_input = QLineEdit()
        self.capitalized_input.setPlaceholderText('Enter count')
        self.capitalized_input.setText('3')

        self.lowercase_label = QLabel('Lowercase:')
        self.lowercase_input = QLineEdit()
        self.lowercase_input.setPlaceholderText('Enter count')
        self.lowercase_input.setText('4')

        self.numbers_label = QLabel('Numbers:')
        self.numbers_input = QLineEdit()
        self.numbers_input.setPlaceholderText('Enter count')
        self.numbers_input.setText('3')

        self.special_label = QLabel('Special:')
        self.special_input = QLineEdit()
        self.special_input.setPlaceholderText('Enter count')
        self.special_input.setText('2')

        self.generate_button = QPushButton('Generate Password')
        self.generate_button.clicked.connect(self.generate_password)  # Connect the button click directly to the slot

        self.password_label = QLabel('Generated Password:')

        self.copy_button = QPushButton('Copy to Clipboard')
        self.copy_button.clicked.connect(self.copy_to_clipboard)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.length_label)
        layout.addWidget(self.length_input)
        layout.addWidget(self.capitalized_label)
        layout.addWidget(self.capitalized_input)
        layout.addWidget(self.lowercase_label)
        layout.addWidget(self.lowercase_input)
        layout.addWidget(self.numbers_label)
        layout.addWidget(self.numbers_input)
        layout.addWidget(self.special_label)
        layout.addWidget(self.special_input)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.password_label)
        layout.addWidget(self.copy_button)

        self.setLayout(layout)

        self.setWindowTitle('Password Generator')
        self.setGeometry(300, 300, 400, 250)
        self.setWindowIcon(QIcon('Pass_Gen.ico'))
        self.show()

    def generate_password(self):
        length_text = self.length_input.text()
        capitalized_text = self.capitalized_input.text()
        lowercase_text = self.lowercase_input.text()
        numbers_text = self.numbers_input.text()
        special_text = self.special_input.text()

        if not length_text or not capitalized_text or not lowercase_text or not numbers_text or not special_text:
            show_error_message("Error", "Please fill in all fields.")
            return

        length = int(length_text)
        capitalized = int(capitalized_text)
        lowercase = int(lowercase_text)
        numbers = int(numbers_text)
        special = int(special_text)

        total_count = capitalized + lowercase + numbers + special

        if total_count > length:
            show_error_message("Error", "Total character count exceeds the specified length.")
            return

        password = []

        for _ in range(capitalized):
            password.append(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ'))

        for _ in range(lowercase):
            password.append(random.choice('abcdefghijklmnopqrstuvwxyz'))

        for _ in range(numbers):
            password.append(random.choice('0123456789'))

        for _ in range(special):
            password.append(random.choice('!@#$%^&*()_-+=<>?/{}[]|'))

        remaining_chars = length - total_count

        password_characters = (
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            'abcdefghijklmnopqrstuvwxyz'
            '0123456789'
            '!@#$%^&*()_-+=<>?/{}[]|'
        )

        for _ in range(remaining_chars):
            password.append(random.choice(password_characters))

        random.shuffle(password)
        generated_password = ''.join(password)
        self.password_label.setText(f"Generated Password: {generated_password}")
        self.generated_password = generated_password  # Store the generated password for copying

    def copy_to_clipboard(self):
        if hasattr(self, 'generated_password') and self.generated_password:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.generated_password)
            show_message("Success", "Password copied to clipboard.")
        else:
            show_error_message("Error", "No password generated to copy.")


if __name__ == '__main__':
    app = QApplication(sys.argv)

    app.setWindowIcon(QIcon('Pass_Gen.ico'))

    ex = PasswordGenerator()
    sys.exit(app.exec_())
