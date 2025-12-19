from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
import io
import math
import hashlib
from base64 import b64encode, b64decode


class Lab1LCGTests(TestCase):
    """Тести для Лабораторної роботи №1 - LCG генератор"""

    def setUp(self):
        self.client = Client()
        self.url = reverse('lcg:lcg')

    def test_lcg_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'lcg/lcg.html')

    def test_gcd_function(self):
        """Тест: Перевірка функції НСД (gcd)"""
        from lcg.views import gcd  # Змініть на актуальний import

        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(100, 50), 50)
        self.assertEqual(gcd(17, 19), 1)  # Взаємно прості
        self.assertEqual(gcd(0, 5), 5)

    def test_lcg_numbers_generation(self):
        """Тест: Перевірка генерації чисел LCG"""
        from lcg.views import lcg_numbers

        m = 2 ** 13 - 1
        a = 5 ** 5
        c = 3
        x0 = 16
        count = 10

        numbers = lcg_numbers(m, a, c, x0, count)

        # Перевірка кількості згенерованих чисел
        self.assertEqual(len(numbers), count)

        # Всі числа повинні бути в діапазоні [0, m)
        for num in numbers:
            self.assertGreaterEqual(num, 0)
            self.assertLess(num, m)

    def test_lcg_period_calculation(self):
        """Тест: Перевірка обчислення періоду LCG"""
        from lcg.views import lcg_period

        m = 2 ** 13 - 1
        a = 5 ** 5
        c = 3
        x0 = 16

        period = lcg_period(m, a, c, x0)

        # Період повинен бути додатнім числом
        self.assertGreater(period, 0)
        # Період не може перевищувати модуль
        self.assertLessEqual(period, m)

    def test_cesaro_estimate(self):
        """Тест: Перевірка методу Чезаро для оцінки π"""
        from lcg.views import cesaro

        # Велика кількість ітерацій для кращої точності
        numbers = list(range(1, 1000))
        estimate = cesaro(numbers, 10000)

        # Оцінка π повинна бути близькою до 3.14159
        self.assertGreater(estimate, 2.5)
        self.assertLess(estimate, 4.0)

    def test_lcg_with_valid_parameters(self):
        """Тест: GET запит з валідними параметрами"""
        response = self.client.get(self.url, {
            'count': 100,
            'count_estimate': 1000
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('result', response.context)
        self.assertIsNotNone(response.context['result'])

    def test_lcg_with_invalid_count(self):
        """Тест: Невалідне значення count (<=1)"""
        response = self.client.get(self.url, {
            'count': 0,
            'count_estimate': 1000
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.context)
        self.assertIsNotNone(response.context['error'])

    def test_lcg_with_too_large_count(self):
        """Тест: Занадто велике значення count"""
        response = self.client.get(self.url, {
            'count': 20000000,
            'count_estimate': 1000
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.context)


class Lab2MD5Tests(TestCase):
    """Тести для Лабораторної роботи №2 - MD5 хешування"""

    def setUp(self):
        self.client = Client()
        self.url = reverse('lab2:lab2')  # Используем namespace lab2

    def test_md5_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'lab2/lab2.html')

    def test_left_rotate(self):
        """Тест: Перевірка лівої циклічної ротації"""
        from lab2.views import left_rotate

        # Тестові випадки для ротації
        result = left_rotate(0x12345678, 8)
        self.assertIsInstance(result, int)
        self.assertLessEqual(result, 0xFFFFFFFF)

    def test_md5_empty_string(self):
        """Тест: MD5 для порожнього рядка"""
        from lab2.views import md5_for_text

        result = md5_for_text('')
        expected = hashlib.md5(b'').hexdigest().upper()
        self.assertEqual(result, expected)

    def test_md5_known_string(self):
        """Тест: MD5 для відомого рядка"""
        from lab2.views import md5_for_text

        test_string = 'hello world'
        result = md5_for_text(test_string)
        expected = hashlib.md5(test_string.encode()).hexdigest().upper()
        self.assertEqual(result, expected)

    def test_md5_unicode_string(self):
        """Тест: MD5 для Unicode рядка (українські символи)"""
        from lab2.views import md5_for_text

        test_string = 'Привіт світ'
        result = md5_for_text(test_string)
        expected = hashlib.md5(test_string.encode('utf-8')).hexdigest().upper()
        self.assertEqual(result, expected)

    def test_hash_text_action(self):
        """Тест: POST запит для хешування тексту"""
        response = self.client.post(self.url, {
            'action': 'hash_text',
            'text': 'test message'
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('md5', response.context)
        self.assertIsNotNone(response.context['md5'])
        self.assertEqual(len(response.context['md5']), 32)  # MD5 має 32 hex символи

    def test_hash_file_action(self):
        """Тест: POST запит для хешування файлу"""
        file_content = b'test file content'
        uploaded_file = SimpleUploadedFile('test.txt', file_content)

        response = self.client.post(self.url, {
            'action': 'hash_file',
            'file': uploaded_file
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('md5', response.context)
        self.assertEqual(response.context['kind'], 'file')

    def test_hash_file_no_file(self):
        """Тест: Хешування файлу без завантаження файлу"""
        response = self.client.post(self.url, {
            'action': 'hash_file'
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('error', response.context)
        self.assertIsNotNone(response.context['error'])

    def test_verify_correct_hash(self):
        """Тест: Верифікація з правильним хешем"""
        file_content = b'verification test'
        uploaded_file = SimpleUploadedFile('verify.txt', file_content)

        # Спочатку обчислюємо правильний хеш
        from lab2.views import md5_bytes
        correct_hash = md5_bytes(file_content)

        response = self.client.post(self.url, {
            'action': 'verify',
            'file': uploaded_file,
            'expected': correct_hash
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['verified'], True)

    def test_verify_incorrect_hash(self):
        """Тест: Верифікація з неправильним хешем"""
        file_content = b'verification test'
        uploaded_file = SimpleUploadedFile('verify.txt', file_content)

        response = self.client.post(self.url, {
            'action': 'verify',
            'file': uploaded_file,
            'expected': '00000000000000000000000000000000'
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['verified'], False)

    def test_download_md5_action(self):
        """Тест: Завантаження .md5 файлу"""
        response = self.client.post(self.url, {
            'action': 'download_md5',
            'md5': 'ABC123DEF456789012345678901234AB',
            'name': 'testfile.txt'
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain')


class Lab3RC5Tests(TestCase):
    """Тести для Лабораторної роботи №3 - RC5 шифрування"""

    def setUp(self):
        self.client = Client()
        self.url = reverse('lab3:lab3')  # Используем namespace lab3

    def test_rc5_page_loads(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'lab3/lab3.html')

    def test_left_rotate_function(self):
        """Тест: Перевірка лівої ротації для RC5"""
        from lab3.views import left_rotate

        result = left_rotate(0x1234, 4, w=16)
        self.assertIsInstance(result, int)
        self.assertLess(result, 2 ** 16)

    def test_right_rotate_function(self):
        """Тест: Перевірка правої ротації для RC5"""
        from lab3.views import right_rotate

        result = right_rotate(0x1234, 4, w=16)
        self.assertIsInstance(result, int)
        self.assertLess(result, 2 ** 16)

    def test_rotate_symmetry(self):
        """Тест: Перевірка симетрії ротацій"""
        from lab3.views import left_rotate, right_rotate

        value = 0x5A5A
        rotated_left = left_rotate(value, 7, w=16)
        rotated_back = right_rotate(rotated_left, 7, w=16)

        self.assertEqual(value, rotated_back)

    def test_pad_bytes(self):
        """Тест: Перевірка доповнення байтів (padding)"""
        from lab3.views import pad_bytes

        data = b'test'
        padded = pad_bytes(data, block_size=4)

        # Довжина повинна бути кратною розміру блоку
        self.assertEqual(len(padded) % 4, 0)
        # Довжина повинна бути більшою за оригінал
        self.assertGreater(len(padded), len(data))

    def test_unpad_bytes(self):
        """Тест: Перевірка зняття доповнення"""
        from lab3.views import pad_bytes, unpad_bytes

        original = b'test data'
        padded = pad_bytes(original, block_size=4)
        unpadded = unpad_bytes(padded)

        self.assertEqual(original, unpadded)

    def test_expand_key(self):
        """Тест: Перевірка розширення ключа"""
        from lab3.views import expand_key

        key = b'testkey1'
        S = expand_key(key, w=16, r=20)

        # Розширений ключ повинен мати 2*(r+1) елементів
        self.assertEqual(len(S), 2 * (20 + 1))
        # Всі елементи повинні бути 16-бітними
        for s in S:
            self.assertLess(s, 2 ** 16)

    def test_rc5_block_encryption_decryption(self):
        """Тест: Перевірка шифрування/розшифрування одного блоку"""
        from lab3.views import expand_key, rc5_encrypt_block, rc5_decrypt_block

        key = b'testkey1'
        S = expand_key(key, w=16, r=20)

        plaintext_block = 0x12345678
        encrypted = rc5_encrypt_block(plaintext_block, S, w=16, r=20)
        decrypted = rc5_decrypt_block(encrypted, S, w=16, r=20)

        self.assertEqual(plaintext_block, decrypted)

    def test_encrypt_text_file(self):
        """Тест: Шифрування текстового файлу"""
        file_content = b'This is a test message for encryption.'
        uploaded_file = SimpleUploadedFile('test.txt', file_content)

        response = self.client.post(self.url, {
            'file': uploaded_file,
            'password': 'testpassword',
            'action': 'encrypt'
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('result_text', response.context)
        self.assertIsNotNone(response.context['result_text'])

        # Результат повинен бути Base64
        result = response.context['result_text']
        try:
            b64decode(result)
            valid_base64 = True
        except:
            valid_base64 = False
        self.assertTrue(valid_base64)

    def test_encrypt_decrypt_cycle(self):
        """Тест: Повний цикл шифрування-розшифрування"""
        original_content = b'Secret message for testing encryption and decryption.'
        password = 'mypassword123'

        # Шифрування
        uploaded_file = SimpleUploadedFile('original.txt', original_content)
        encrypt_response = self.client.post(self.url, {
            'file': uploaded_file,
            'password': password,
            'action': 'encrypt'
        })

        self.assertEqual(encrypt_response.status_code, 200)
        encrypted_text = encrypt_response.context['result_text']

        # Розшифрування
        encrypted_bytes = b64encode(b64decode(encrypted_text))
        decrypt_file = SimpleUploadedFile('encrypted.txt', encrypted_bytes)
        decrypt_response = self.client.post(self.url, {
            'file': decrypt_file,
            'password': password,
            'action': 'decrypt'
        })

        self.assertEqual(decrypt_response.status_code, 200)
        decrypted_text = decrypt_response.context['result_text']

        # Розшифрований текст повинен збігатися з оригіналом
        self.assertEqual(original_content.decode('cp1252'), decrypted_text)

    def test_decrypt_with_wrong_password(self):
        """Тест: Розшифрування з неправильним паролем"""
        # Спочатку шифруємо
        original_content = b'Secret data'
        correct_password = 'correct123'

        uploaded_file = SimpleUploadedFile('test.txt', original_content)
        encrypt_response = self.client.post(self.url, {
            'file': uploaded_file,
            'password': correct_password,
            'action': 'encrypt'
        })

        encrypted_text = encrypt_response.context['result_text']

        # Спробуємо розшифрувати з неправильним паролем
        encrypted_bytes = b64encode(b64decode(encrypted_text))
        decrypt_file = SimpleUploadedFile('encrypted.txt', encrypted_bytes)
        decrypt_response = self.client.post(self.url, {
            'file': decrypt_file,
            'password': 'wrongpassword',
            'action': 'decrypt'
        })

        # Розшифрування не повинно повернути оригінальний текст
        decrypted_text = decrypt_response.context.get('result_text', '')
        self.assertNotEqual(original_content.decode('cp1252'), decrypted_text)

    def test_timing_measurements(self):
        """Тест: Перевірка вимірювання часу виконання"""
        file_content = b'Test content for timing measurement.'
        uploaded_file = SimpleUploadedFile('timing.txt', file_content)

        response = self.client.post(self.url, {
            'file': uploaded_file,
            'password': 'testpass',
            'action': 'encrypt'
        })

        self.assertEqual(response.status_code, 200)
        # Перевірка наявності даних про час виконання
        self.assertIn('key_setup_time', response.context)
        self.assertIn('operation_time', response.context)
        self.assertIn('time_elapsed', response.context)

    def test_form_validation(self):
        """Тест: Валідація форми"""
        # Тест без файлу
        response = self.client.post(self.url, {
            'password': 'testpass',
            'action': 'encrypt'
        })

        # Форма повинна бути невалідною
        self.assertEqual(response.status_code, 200)


# Інтеграційні тести
def test_md5_and_rc5_integration(self):
    from lab3.views import md5_for_text, expand_key

    password = 'integration_test'
    key_full = md5_for_text(password)
    key = key_full[:8]

    S = expand_key(key, w=16, r=20)

    self.assertIsNotNone(S)
    self.assertEqual(len(S), 42)


def test_all_pages_accessible(self):
    """Проверка доступности всех страниц"""
    urls = [
        reverse('lcg:lcg'),
        reverse('lab2:lab2'),
        reverse('lab3:lab3'),
        reverse('lab4:lab4_rsa'),
        reverse('lab5:lab5'),
    ]

    for url in urls:
        try:
            response = self.client.get(url)
            self.assertIn(response.status_code, [200, 301, 302])
        except Exception as e:
            self.fail(f"Failed to access {url}: {str(e)}")