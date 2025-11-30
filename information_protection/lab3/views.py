from django.shortcuts import render
from django import forms
import hashlib
import io
from base64 import b64encode

def md5_for_text(s: str) -> bytes:
    return hashlib.md5(s.encode()).digest()

def generate_lcg(seed=12345, n=4):
    m = 2**32
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
    for i in range(len(key_bytes)-1, -1, -1):
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
    return data + bytes([pad_len] * pad_len)

def unpad_bytes(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > len(data):
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
    from django.template import loader, TemplateDoesNotExist
    template_name = None
    try:
        loader.get_template('lab3/lab3.htm')
        template_name = 'lab3/lab3.htm'
    except TemplateDoesNotExist:
        try:
            loader.get_template('lab3/lab3.html')
            template_name = 'lab3/lab3.html'
        except TemplateDoesNotExist:
            template_name = 'lab3/lab3.htm'

    result_text = None
    out_name = None

    if request.method == 'POST' and 'file' in request.FILES:
        form = Lab3Form(request.POST, request.FILES)
        if form.is_valid():
            uploaded = request.FILES['file']
            password = form.cleaned_data['password']
            action = form.cleaned_data['action']

            data = uploaded.read()
            key_full = md5_for_text(password)
            key = key_full[:8]
            S = expand_key(key, w=16, r=20)
            block_size = 4

            if action == 'encrypt':
                data_padded = pad_bytes(data, block_size)
                seed = sum(key)
                iv = generate_lcg(seed=seed, n=block_size)
                prev = int.from_bytes(iv, 'big')
                ciphertext = bytearray()
                for i in range(0, len(data_padded), block_size):
                    p_block_bytes = data_padded[i:i+block_size]
                    p_block = int.from_bytes(p_block_bytes, 'big')
                    x = p_block ^ prev
                    c_block = rc5_encrypt_block(x, S, w=16, r=20)
                    ciphertext += c_block.to_bytes(block_size, 'big')
                    prev = c_block
                final_bytes = iv + bytes(ciphertext)
                out_name = uploaded.name + ".enc"

            else:  # decrypt
                data_bytes = data
                try:
                    txt = data.decode('utf-8').strip()
                    if len(txt) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in txt):
                        data_bytes = bytes.fromhex(txt)
                except Exception:
                    pass

                if len(data_bytes) < block_size:
                    return render(request, template_name, {'form': form, 'error': 'Файл занадто короткий або не є зашифрованим.'})

                iv = data_bytes[:block_size]
                ciphertext = data_bytes[block_size:]
                prev = int.from_bytes(iv, 'big')
                plaintext = bytearray()
                for i in range(0, len(ciphertext), block_size):
                    c_block_bytes = ciphertext[i:i+block_size]
                    c_block = int.from_bytes(c_block_bytes, 'big')
                    dec = rc5_decrypt_block(c_block, S, w=16, r=20) ^ prev
                    plaintext += dec.to_bytes(block_size, 'big')
                    prev = c_block
                final_bytes = unpad_bytes(bytes(plaintext))
                out_name = uploaded.name
                if out_name.endswith('.enc'):
                    out_name = out_name[:-4]

            # Вивід на екран: base64 для бінарних даних
            result_text = b64encode(final_bytes).decode('ascii')

            return render(request, template_name, {
                'form': form,
                'result_text': result_text,
                'filename': out_name
            })

    else:
        form = Lab3Form()

    return render(request, template_name, {'form': form})
