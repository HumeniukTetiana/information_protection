from django.shortcuts import render
from django import forms
import hashlib
import io
from base64 import b64encode, b64decode
from django.template import loader, TemplateDoesNotExist
import time  # <--- ДОДАНО: Імпорт модуля time


# --- Утилітарні функції (залишені без змін згідно з вимогою) ---

def md5_for_text(s: str) -> bytes:
    return hashlib.md5(s.encode()).digest()


def generate_lcg(seed=12345, n=4):
    m = 2 ** 32
    a = 1103515245
    c = 12345
    result = []
    x = seed & 0xFFFFFFFF
    for _ in range(n):
        x = (a * x + c) % m
        result.append(x & 0xFF)
    return bytes(result)


def left_rotate(x, n, w=16):
    n %= w
    return ((x << n) | (x >> (w - n))) & ((1 << w) - 1)


def right_rotate(x, n, w=16):
    n %= w
    return ((x >> n) | (x << (w - n))) & ((1 << w) - 1)


def expand_key(key_bytes, w=16, r=20):
    u = w // 8
    c = max(1, (len(key_bytes) + u - 1) // u)
    L = [0] * c
    for i in range(len(key_bytes) - 1, -1, -1):
        L[i // u] = (L[i // u] << 8) + key_bytes[i]

    P = 0xB7E1
    Q = 0x9E37
    S = [0] * (2 * (r + 1))
    S[0] = P & 0xFFFF
    for i in range(1, 2 * (r + 1)):
        S[i] = (S[i - 1] + Q) & 0xFFFF

    i = j = 0
    A = B = 0
    n = 3 * max(len(S), len(L))
    for _ in range(n):
        A = S[i] = left_rotate((S[i] + A + B) & 0xFFFF, 3, w)
        B = L[j] = left_rotate((L[j] + A + B) & 0xFFFF, (A + B) & 0xF, w)
        i = (i + 1) % len(S)
        j = (j + 1) % len(L)
    return S


def rc5_encrypt_block(block, S, w=16, r=20):
    mask = (1 << w) - 1
    A = (block >> w) & mask
    B = block & mask
    A = (A + S[0]) & mask
    B = (B + S[1]) & mask
    for i in range(1, r + 1):
        A = (left_rotate(A ^ B, B & (w - 1), w) + S[2 * i]) & mask
        B = (left_rotate(B ^ A, A & (w - 1), w) + S[2 * i + 1]) & mask
    return (A << w) | B


def rc5_decrypt_block(block, S, w=16, r=20):
    mask = (1 << w) - 1
    A = (block >> w) & mask
    B = block & mask
    for i in range(r, 0, -1):
        B = right_rotate((B - S[2 * i + 1]) & mask, A & (w - 1), w) ^ A
        A = right_rotate((A - S[2 * i]) & mask, B & (w - 1), w) ^ B
    B = (B - S[1]) & mask
    A = (A - S[0]) & mask
    return (A << w) | B


def pad_bytes(data: bytes, block_size: int = 4) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    # Використовуємо PKCS#7-подібне доповнення: значення байта дорівнює довжині доповнення
    return data + bytes([pad_len] * pad_len)


def unpad_bytes(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    # Перевірка на коректність доповнення
    if pad_len <= 0 or pad_len > len(data) or data[-pad_len:] != bytes([pad_len] * pad_len):
        # Якщо доповнення некоректне, повертаємо дані як є (можливо, розшифрування невдале)
        return data
    return data[:-pad_len]


# ---------------- Forms ----------------
class Lab3Form(forms.Form):
    file = forms.FileField(label="Виберіть файл")
    password = forms.CharField(widget=forms.PasswordInput, label="Парольна фраза")
    action = forms.ChoiceField(
        choices=[('encrypt', 'Зашифрувати'), ('decrypt', 'Розшифрувати')],
        label="Дія"
    )


# ---------------- View ----------------
def lab3_view(request):
    loader.get_template('lab3/lab3.html')
    template_name = 'lab3/lab3.html'

    result_text = None
    out_name = None
    error = None
    time_elapsed = None  # <--- ДОДАНО: Змінна для часу

    if request.method == 'POST' and 'file' in request.FILES:
        form = Lab3Form(request.POST, request.FILES)
        if form.is_valid():
            uploaded = request.FILES['file']
            password = form.cleaned_data['password']
            action = form.cleaned_data['action']

            data = uploaded.read()

            # Встановлення параметрів RC5/CBC
            block_size = 4  # 2w / 8 = 32 біти = 4 байти
            w = 16
            r = 20

            # Генерація ключа
            key_full = md5_for_text(password)
            key = key_full[:8]  # Використовуємо 8 байт (64 біти) ключа
            S = expand_key(key, w=w, r=r)

            start_time = time.perf_counter() # <--- ДОДАНО: Початок вимірювання часу

            if action == 'encrypt':
                # --- Шифрування: RC5 у режимі CBC ---

                # 1. Доповнення
                data_padded = pad_bytes(data, block_size)

                # 2. Генерація IV
                seed = sum(key)  # Seed для LCG
                iv = generate_lcg(seed=seed, n=block_size)
                prev = int.from_bytes(iv, 'big')  # Попередній шифроблок (IV)

                ciphertext = bytearray()

                # 3. Шифрування блоків
                for i in range(0, len(data_padded), block_size):
                    p_block_bytes = data_padded[i:i + block_size]
                    p_block = int.from_bytes(p_block_bytes, 'big')

                    # p_block XOR prev
                    x = p_block ^ prev
                    # Encrypt(x)
                    c_block = rc5_encrypt_block(x, S, w=w, r=r)
                    # Додавання до шифрованого тексту
                    ciphertext += c_block.to_bytes(block_size, 'big')

                    # Оновлення попереднього блоку
                    prev = c_block

                # 4. Формування кінцевих байтів (IV + Ciphertext)
                final_bytes = iv + bytes(ciphertext)
                out_name = "enc_"+ uploaded.name

                # 5. Вивід: Base64-кодування для відображення в тексті
                # Це виводить зашифровані дані (Base64-рядок)
                result_text = b64encode(final_bytes).decode('ascii')

            else:  # decrypt
                # --- Розшифрування: RC5 у режимі CBC ---

                data_bytes = data

                # 1. Спроба декодувати Base64, якщо файл був завантажений як Base64-текст
                try:
                    txt = data.decode('utf-8').strip()
                    # Припускаємо Base64, якщо це не чистий hex
                    if len(txt) > 0 and not all(c in "0123456789abcdefABCDEF" for c in txt):
                        # data_bytes тепер містить бінарний шифртекст
                        data_bytes = b64decode(txt)
                except Exception:
                    # Якщо декодування не вдалося, залишаємо data_bytes як є (чисті бінарні дані).
                    pass

                if len(data_bytes) < block_size + 1:  # IV + хоча б один байт
                    error = 'Файл занадто короткий, можливо, не є зашифрованим або пошкоджений.'
                    return render(request, template_name, {'form': form, 'error': error})

                # 2. Виділення IV
                iv = data_bytes[:block_size]
                ciphertext = data_bytes[block_size:]

                if len(ciphertext) % block_size != 0:
                    error = 'Довжина шифрованого тексту некоректна (не кратна розміру блоку).'
                    return render(request, template_name, {'form': form, 'error': error})

                prev = int.from_bytes(iv, 'big')
                plaintext = bytearray()

                # 3. Розшифрування блоків
                for i in range(0, len(ciphertext), block_size):
                    c_block_bytes = ciphertext[i:i + block_size]
                    c_block = int.from_bytes(c_block_bytes, 'big')

                    # Decrypt(c_block)
                    decrypted_block_int = rc5_decrypt_block(c_block, S, w=w, r=r)

                    # decrypted_block XOR prev (IV/попередній шифроблок)
                    p_block = decrypted_block_int ^ prev

                    # Додавання до відкритого тексту
                    plaintext += p_block.to_bytes(block_size, 'big')

                    # Оновлення попереднього блоку
                    prev = c_block

                # 4. Зняття доповнення
                final_bytes = unpad_bytes(bytes(plaintext))

                # 5. Формування імені файлу
                out_name = uploaded.name
                out_name = out_name

                decoded_text = final_bytes.decode('cp1252')
                # Заміна символів повернення каретки (\r\n) для чистого виводу тексту
                result_text = decoded_text.replace('\r\n', '\n')

            end_time = time.perf_counter() # <--- ДОДАНО: Кінець вимірювання часу
            time_elapsed = end_time - start_time # <--- ДОДАНО: Обчислення часу

            return render(request, template_name, {
                'form': form,
                'result_text': result_text,
                'filename': out_name,
                'time_elapsed': f"{time_elapsed:.6f}" # <--- ДОДАНО: Передача часу у контекст
            })

    else:
        form = Lab3Form()

    return render(request, template_name, {'form': form, 'error': error})