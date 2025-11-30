# lab3/views.py
from django.shortcuts import render
from django import forms
from django.http import FileResponse
from django.template import loader, TemplateDoesNotExist
import io
import hashlib



# ---------------- MD5 ----------------
def md5_for_text(s: str) -> bytes:
    """MD5 от тексту → 16 байт"""
    return hashlib.md5(s.encode()).digest()

# ---------------- LCG ----------------
def generate_lcg(seed=12345, n=4):
    """
    Простий LCG (реалізація з lab1).
    Повертає n байтів IV (тут зазвичай n = block_size = 4).
    """
    m = 2**32
    a = 1103515245
    c = 12345
    result = []
    x = seed & 0xFFFFFFFF
    for _ in range(n):
        x = (a * x + c) % m
        result.append(x & 0xFF)
    return bytes(result)

# ---------------- RC5 (ручна реалізація для w=16, r=20) ----------------
def left_rotate(x, n, w=16):
    n = n % w
    return ((x << n) | (x >> (w - n))) & ((1 << w) - 1)

def right_rotate(x, n, w=16):
    n = n % w
    return ((x >> n) | (x << (w - n))) & ((1 << w) - 1)

def expand_key(key_bytes, w=16, r=20):
    """
    Розширення ключа (key schedule), повертає масив S довжини 2*(r+1).
    Взято/адаптовано під w=16.
    """
    u = w // 8  # байтів у слові (16 бит -> 2 байти)
    # c = кількість слів у L (вхідний ключ як масив слів)
    c = max(1, (len(key_bytes) + u - 1) // u)
    L = [0] * c
    # розбиваємо key_bytes у слова L (молодші байти перші)
    for i in range(len(key_bytes)-1, -1, -1):
        L[i // u] = (L[i // u] << 8) + key_bytes[i]

    # Константи для w=16 (взято аналогічно RC5 P, Q, але обрізані до 16 біт)
    P = 0xB7E1  # Aprox, використано у попередньому коді
    Q = 0x9E37
    S = [0] * (2 * (r + 1))
    S[0] = P & 0xFFFF
    for i in range(1, 2 * (r + 1)):
        S[i] = (S[i - 1] + Q) & 0xFFFF

    # Змішування S і L
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
    """
    Шифрування одного 2-word блоку (A,B): block має розмір 2*w біт (тут 32 біти -> 4 байти).
    Повертаємо 32-бітне число.
    """
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
    """
    Дешифрування одного блоку (32 біт).
    """
    mask = (1 << w) - 1
    A = (block >> w) & mask
    B = block & mask
    for i in range(r, 0, -1):
        B = right_rotate((B - S[2 * i + 1]) & mask, A & (w - 1), w) ^ A
        A = right_rotate((A - S[2 * i]) & mask, B & (w - 1), w) ^ B
    B = (B - S[1]) & mask
    A = (A - S[0]) & mask
    return (A << w) | B

# ---------------- CBC + Pad (block_size = 4 bytes -> 32 bits) ----------------
def pad_bytes(data: bytes, block_size: int = 4) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)

def unpad_bytes(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > len(data):
        # некоректний паддінг — повернути як є (щоб не падати)
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
    """
    Повністю самодостатня view: MD5, LCG, RC5 (ручний), CBC-Pad.
    Повертає файл у відповіді (FileResponse) для завантаження.
    Також реалізовано fallback для імені шаблона (.htm або .html).
    """
    template_name = None
    # намагаємось знайти шаблон lab3/lab3.htm, якщо нема — lab3/lab3.html
    try:
        loader.get_template('lab3/lab3.htm')
        template_name = 'lab3/lab3.htm'
    except TemplateDoesNotExist:
        try:
            loader.get_template('lab3/lab3.html')
            template_name = 'lab3/lab3.html'
        except TemplateDoesNotExist:
            # Якщо шаблонів нема — встановимо стандартне ім'я (render викине помилку далі)
            template_name = 'lab3/lab3.htm'

    if request.method == 'POST' and 'file' in request.FILES:
        form = Lab3Form(request.POST, request.FILES)
        if form.is_valid():
            uploaded = request.FILES['file']
            password = form.cleaned_data['password']
            action = form.cleaned_data['action']

            data = uploaded.read()  # байти!
            # ключ: MD5(password), беремо молодші 64 біти (8 байт)
            key_full = md5_for_text(password)  # 16 байт
            key = key_full[:8]  # 8 байт (64 біт)
            # Підготовка розширеного ключа
            S = expand_key(key, w=16, r=20)

            block_size = 4  # 4 байти = 32 біт (2 слова по 16 біт)

            if action == 'encrypt':
                # паддінг
                data_padded = pad_bytes(data, block_size)
                # IV генеруємо 4 байти
                seed = sum(key)  # простий повідник для LCG seed
                iv = generate_lcg(seed=seed, n=block_size)
                prev = int.from_bytes(iv, 'big')
                ciphertext = bytearray()
                # CBC: C_i = E(P_i XOR C_{i-1})
                for i in range(0, len(data_padded), block_size):
                    p_block_bytes = data_padded[i:i+block_size]
                    p_block = int.from_bytes(p_block_bytes, 'big')
                    x = p_block ^ prev
                    c_block = rc5_encrypt_block(x, S, w=16, r=20)
                    ciphertext += c_block.to_bytes(block_size, 'big')
                    prev = c_block  # для наступного блоку
                final_bytes = iv + bytes(ciphertext)
                out_name = uploaded.name + ".enc"
                # Віддаємо як бінарний файл
                bio = io.BytesIO(final_bytes)
                bio.seek(0)
                return FileResponse(bio, as_attachment=True, filename=out_name, content_type='application/octet-stream')

            else:  # decrypt
                # data має бути байтами: перші block_size байт - IV
                # Додатково: якщо користувач випадково завантажив hex-рядок, спробуємо перетворити
                data_bytes = data
                # Спроба: якщо весь файл - ASCII-hex (тільки 0-9a-fA-F і парна довжина), перетворимо
                try_hex = False
                try:
                    txt = data.decode('utf-8').strip()
                    # перевірка чи hex-рядок
                    if len(txt) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in txt):
                        try_hex = True
                except Exception:
                    try_hex = False
                if try_hex:
                    try:
                        data_bytes = bytes.fromhex(txt)
                    except Exception:
                        # якщо не вдалось, залишаємо як є
                        data_bytes = data

                if len(data_bytes) < block_size:
                    # некоректні вхідні дані
                    return render(request, template_name, {'form': form, 'error': 'Файл занадто короткий або не є зашифрованим.'})

                iv = data_bytes[:block_size]
                ciphertext = data_bytes[block_size:]
                if len(ciphertext) % block_size != 0:
                    return render(request, template_name, {'form': form, 'error': 'Некоректна довжина шифртексту.'})

                prev = int.from_bytes(iv, 'big')
                plaintext = bytearray()
                for i in range(0, len(ciphertext), block_size):
                    c_block_bytes = ciphertext[i:i+block_size]
                    c_block = int.from_bytes(c_block_bytes, 'big')
                    # D = D_RC5(C) XOR prev
                    dec = rc5_decrypt_block(c_block, S, w=16, r=20) ^ prev
                    plaintext += dec.to_bytes(block_size, 'big')
                    prev = c_block

                # видаляємо паддінг
                final_bytes = unpad_bytes(bytes(plaintext))
                out_name = uploaded.name
                # Якщо файл, скоріше за все, був .enc, можемо знімати .enc замість додавати суфікс
                if out_name.endswith('.enc'):
                    out_name = out_name[:-4]
                else:
                    out_name = out_name

                bio = io.BytesIO(final_bytes)
                bio.seek(0)
                return FileResponse(bio, as_attachment=True, filename=out_name, content_type='application/octet-stream')

    else:
        form = Lab3Form()

    return render(request, template_name, {'form': form})
