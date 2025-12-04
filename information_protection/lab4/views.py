import time
import base64
from django.shortcuts import render
from django.http import HttpResponse

# --- CRYPTOGRAPHY RSA ---
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# --- RC5 MANUAL (as provided by user) ---
WORD_SIZE = 32
BLOCK_SIZE = 2
ROUNDS = 12
P = 0xB7E15163
Q = 0x9E3779B9


def rotl(x, y):
    """Circular left shift for 32-bit word."""
    return ((x << y) | (x >> (32 - y))) & 0xFFFFFFFF


def rotr(x, y):
    """Circular right shift for 32-bit word."""
    return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF


def rc5_key_schedule(key: bytes):
    u = WORD_SIZE // 8
    c = max(1, len(key) // u)
    L = [0] * c
    for i in range(len(key)):
        L[i // u] = (L[i // u] + (key[i] << (8 * (i % u)))) & 0xFFFFFFFF
    S = [0] * (2 * ROUNDS + 2)
    S[0] = P
    for i in range(1, len(S)):
        S[i] = (S[i - 1] + Q) & 0xFFFFFFFF
    i = j = 0
    A = B = 0
    for k in range(3 * max(len(S), c)):
        A = S[i] = rotl((S[i] + A + B), 3)
        B = L[j] = rotl((L[j] + A + B), 3)
        i = (i + 1) % len(S)
        j = (j + 1) % c
    return S


def rc5_encrypt_block(data, S):
    A = int.from_bytes(data[:4], "little")
    B = int.from_bytes(data[4:], "little")
    A = (A + S[0]) & 0xFFFFFFFF
    B = (B + S[1]) & 0xFFFFFFFF
    for i in range(1, ROUNDS + 1):
        A = (rotl(A ^ B, B) + S[2 * i]) & 0xFFFFFFFF
        B = (rotl(B ^ A, A) + S[2 * i + 1]) & 0xFFFFFFFF
    return A.to_bytes(4, "little") + B.to_bytes(4, "little")


def rc5_decrypt_block(data, S):
    A = int.from_bytes(data[:4], "little")
    B = int.from_bytes(data[4:], "little")
    for i in range(ROUNDS, 0, -1):
        B = (rotr(B - S[2 * i + 1], A) ^ A) & 0xFFFFFFFF
        A = (rotr(A - S[2 * i], B) ^ B) & 0xFFFFFFFF
    B = (B - S[1]) & 0xFFFFFFFF
    A = (A - S[0]) & 0xFFFFFFFF
    return A.to_bytes(4, "little") + B.to_bytes(4, "little")


def rc5_encrypt(data: bytes, key: bytes):
    S = rc5_key_schedule(key)
    encrypted = b""
    padding_len = 8 - (len(data) % 8) if len(data) % 8 != 0 else 8  # Must be 8 if len % 8 == 0
    padded_data = data + bytes([padding_len]) * padding_len
    for i in range(0, len(padded_data), 8):
        block = padded_data[i:i + 8]
        encrypted += rc5_encrypt_block(block, S)
    return encrypted


def rc5_decrypt(data: bytes, key: bytes):
    S = rc5_key_schedule(key)
    decrypted = b""
    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        decrypted += rc5_decrypt_block(block, S)
    if not decrypted:
        return b""
    padding_len = decrypted[-1]
    if padding_len > 8 or padding_len == 0:
        return decrypted  # Invalid padding, return as is or handle error
    return decrypted[:-padding_len]


# --- DJANGO VIEW ---
def lab4(request):
    # CRITICAL FIX: Initialize context variables
    context = {
        'message': None,
        'error': None,
        'private_key': None,
        'public_key': None,
        'enc_time': None,
        'enc_size': None,
        'dec_time': None,
        'dec_size': None,
        'file_size': None,
        'cipher_type': None,
        # Додаємо поля для Base64 даних
        'encrypted_data_base64': None,
        'decrypted_data_base64': None,
        'encrypted_filename': None,
        'decrypted_filename': None,
    }

    if request.method == "POST":
        action = request.POST.get("action")

        # ------------------ Генерація RSA ключів ------------------
        if action == "generate_keys":
            try:
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                private_bytes = key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                public_bytes = key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                # ВИДАЛЕНО: Збереження ключів на диск (для надійності в ізольованих середовищах)

                context[
                    "message"] = "RSA ключі успішно згенеровано. Ви можете скопіювати їх або завантажити на свій комп'ютер."
                context["private_key"] = private_bytes.decode()
                context["public_key"] = public_bytes.decode()

            except Exception as e:
                context["error"] = f"Помилка при генерації ключів: {e}"


        # ------------------ Шифрування файлу RSA ------------------
        elif action == "encrypt_rsa":
            data_file = request.FILES.get("data_file")
            public_key_file = request.FILES.get("public_key_file")

            if data_file is None or public_key_file is None:
                context["error"] = "Не вибрано файл даних та/або файл публічного ключа."
            else:
                try:
                    public_key_bytes = public_key_file.read()
                    public_key = serialization.load_pem_public_key(public_key_bytes)

                    data = data_file.read()
                    context["file_size"] = len(data)
                    context["cipher_type"] = "RSA"

                    start = time.time()

                    # Максимальний розмір даних для шифрування = 2048/8 - 66 = 190 байт
                    # (для ключа 2048 і OAEP з SHA256)
                    chunk_size = 190
                    encrypted = b""

                    for i in range(0, len(data), chunk_size):
                        chunk = data[i:i + chunk_size]
                        encrypted += public_key.encrypt(
                            chunk,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                    end = time.time()

                    # 3. Збереження результатів та підготовка до відображення/завантаження
                    context["enc_time"] = round(end - start, 10)
                    context["enc_size"] = len(encrypted)

                    # Кодуємо дані для передачі в HTML через Base64
                    context["encrypted_data_base64"] = base64.b64encode(encrypted).decode('utf-8')

                    # --- ОНОВЛЕННЯ ІМЕНІ ФАЙЛУ ---
                    original_filename = data_file.name
                    if '.' in original_filename:
                        name_parts = original_filename.rsplit('.', 1)
                        # rsa_filename.ext
                        context["encrypted_filename"] = f"rsa_{name_parts[0]}.{name_parts[1]}"
                    else:
                        # rsa_filename
                        context["encrypted_filename"] = f"rsa_{original_filename}"

                    context[
                        "message"] = f"Файл '{data_file.name}' успішно зашифровано RSA. Результати та посилання на завантаження знаходяться нижче."

                except Exception as e:
                    context[
                        "error"] = f"Помилка шифрування RSA: Переконайтеся, що вибрано коректний публічний ключ (.pem). Деталі: {e}"


        # ------------------ Розшифрування файлу RSA ------------------
        elif action == "decrypt_rsa":
            encrypted_file = request.FILES.get("encrypted_file")
            private_key_file = request.FILES.get("private_key_file")

            if encrypted_file is None or private_key_file is None:
                context["error"] = "Не вибрано зашифрований файл та/або файл приватного ключа."
            else:
                try:
                    private_key_bytes = private_key_file.read()
                    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)

                    encrypted_data = encrypted_file.read()
                    context["file_size"] = len(encrypted_data)
                    context["cipher_type"] = "RSA"

                    start = time.time()

                    # Розмір блоку для розшифрування = розміру ключа = 256 байт (2048 біт)
                    chunk_size = 256
                    decrypted = b""

                    for i in range(0, len(encrypted_data), chunk_size):
                        chunk = encrypted_data[i:i + chunk_size]
                        decrypted += private_key.decrypt(
                            chunk,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                    end = time.time()

                    # 3. Збереження результатів та підготовка до відображення/завантаження
                    context["dec_time"] = round(end - start, 5)
                    context["dec_size"] = len(decrypted)

                    # Кодуємо дані для передачі в HTML через Base64
                    context["decrypted_data_base64"] = base64.b64encode(decrypted).decode('utf-8')

                    # --- ОНОВЛЕННЯ ІМЕНІ ФАЙЛУ ---
                    original_filename = encrypted_file.name
                    # Видаляємо '.rsa' (якщо присутній)
                    original_filename_no_rsa = original_filename.replace(".rsa", "")

                    if '.' in original_filename_no_rsa:
                        name_parts = original_filename_no_rsa.rsplit('.', 1)
                        # dec_filename.ext
                        context["decrypted_filename"] = f"dec_{name_parts[0]}.{name_parts[1]}"
                    else:
                        # dec_filename
                        context["decrypted_filename"] = f"dec_{original_filename_no_rsa}"

                    context[
                        "message"] = f"Файл '{encrypted_file.name}' успішно розшифровано RSA. Результати та посилання на завантаження знаходяться нижче."

                except InvalidSignature as e:
                    context[
                        "error"] = "Помилка розшифрування: Некоректний приватний ключ або пошкоджені дані. Спробуйте інший ключ."
                except Exception as e:
                    context[
                        "error"] = f"Помилка розшифрування RSA: Переконайтеся, що вибрано коректний приватний ключ (.pem) та файл (.rsa). Деталі: {e}"

    # Це єдиний вихід для відображення сторінки
    return render(request, "lab4/lab4.html", context)