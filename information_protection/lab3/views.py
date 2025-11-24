from django.shortcuts import render
from django import forms
from django.http import FileResponse
import io
import hashlib

# ---------------- MD5 ----------------
def md5_for_text(s: str) -> bytes:
    return hashlib.md5(s.encode()).digest()

# ---------------- LCG ----------------
def generate_lcg(seed=12345, n=8):
    m = 2**32
    a = 1103515245
    c = 12345
    result = []
    x = seed
    for _ in range(n):
        x = (a*x + c) % m
        result.append(x & 0xFF)
    return bytes(result)

# ---------------- RC5 ----------------
def left_rotate(x, n, w=16):
    return ((x << n) | (x >> (w - n))) & (2**w - 1)

def right_rotate(x, n, w=16):
    return ((x >> n) | (x << (w - n))) & (2**w - 1)

def expand_key(key_bytes, w=16, r=20):
    u = w // 8
    c = max(1, len(key_bytes)//u)
    L = [0]*c
    for i in range(len(key_bytes)-1, -1, -1):
        L[i//u] = (L[i//u] << 8) + key_bytes[i]
    P = 0xB7E1
    Q = 0x9E37
    S = [0]*(2*(r+1))
    S[0] = P
    for i in range(1, 2*(r+1)):
        S[i] = (S[i-1] + Q) & 0xFFFF
    i = j = 0
    A = B = 0
    n = max(len(S), len(L))*3
    for _ in range(n):
        A = S[i] = left_rotate((S[i]+A+B) & 0xFFFF, 3)
        B = L[j] = left_rotate((L[j]+A+B) & 0xFFFF, (A+B) & 0xF)
        i = (i+1) % len(S)
        j = (j+1) % len(L)
    return S

def rc5_encrypt_block(block, S, w=16, r=20):
    mask = 2**w - 1
    A = block >> w
    B = block & mask
    A = (A + S[0]) & mask
    B = (B + S[1]) & mask
    for i in range(1, r+1):
        A = (left_rotate(A ^ B, B & (w-1)) + S[2*i]) & mask
        B = (left_rotate(B ^ A, A & (w-1)) + S[2*i+1]) & mask
    return (A << w) | B

def rc5_decrypt_block(block, S, w=16, r=20):
    mask = 2**w - 1
    A = block >> w
    B = block & mask
    for i in range(r, 0, -1):
        B = right_rotate((B - S[2*i+1]) & mask, A & (w-1)) ^ A
        A = right_rotate((A - S[2*i]) & mask, B & (w-1)) ^ B
    B = (B - S[1]) & mask
    A = (A - S[0]) & mask
    return (A << w) | B

# ---------------- CBC Pad ----------------
def pad_bytes(data, block_size=4):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]*pad_len)

def unpad_bytes(data):
    pad_len = data[-1]
    return data[:-pad_len]

# ---------------- Forms ----------------
class Lab3Form(forms.Form):
    file = forms.FileField(label="Виберіть файл")
    password = forms.CharField(widget=forms.PasswordInput, label="Парольна фраза")
    action = forms.ChoiceField(choices=[('encrypt','Зашифрувати'),('decrypt','Розшифрувати')])

def lab3_view(request):
    if request.method == 'POST' and 'file' in request.FILES:
        form = Lab3Form(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            password = form.cleaned_data['password']
            action = form.cleaned_data['action']
            data = file.read()
            key = hashlib.md5(password.encode()).digest()[:8]
            S = expand_key(key)
            block_size = 4

            if action == 'encrypt':
                data = pad_bytes(data, block_size)
                iv = generate_lcg(seed=sum(key))
                ciphertext = bytearray()
                prev = int.from_bytes(iv, 'big')
                for i in range(0, len(data), block_size):
                    block = int.from_bytes(data[i:i+block_size], 'big') ^ prev
                    enc_block = rc5_encrypt_block(block, S)
                    prev = enc_block
                    ciphertext += enc_block.to_bytes(block_size, 'big')
                final_bytes = iv + ciphertext
                filename = file.name + "_encrypted.txt"

            else:  # decrypt
                try:
                    data_bytes = bytes.fromhex(data.decode('utf-8'))
                except:
                    data_bytes = data
                iv = data_bytes[:block_size]
                ciphertext = data_bytes[block_size:]
                plaintext = bytearray()
                prev = int.from_bytes(iv, 'big')
                for i in range(0, len(ciphertext), block_size):
                    block = int.from_bytes(ciphertext[i:i+block_size], 'big')
                    dec_block = rc5_decrypt_block(block, S) ^ prev
                    prev = block
                    plaintext += dec_block.to_bytes(block_size, 'big')
                final_bytes = unpad_bytes(plaintext)
                filename = file.name + "_decrypted.txt"

            # Відправляємо результат як файл
            file_io = io.BytesIO(final_bytes)
            file_io.seek(0)
            return FileResponse(file_io, as_attachment=True, filename=filename)

    else:
        form = Lab3Form()

    return render(request, 'lab3/lab3.html', {'form': form})