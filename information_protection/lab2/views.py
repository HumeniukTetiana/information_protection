from django.shortcuts import render
from django.http import HttpResponse, FileResponse
import io
import os
import struct

CHUNK_SIZE = 8 * 1024 * 1024

# Ліва кругова ротація
def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

# MD5 обчислення для байтів
def md5_bytes(message_bytes):
    # Ініціалізація
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    # Синуси
    T = [int(abs(__import__('math').sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    # Кроки зсувів
    S = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    ]

    # Додає нулі поки довжина % 512 = 448
    msg_len_bits = (8 * len(message_bytes)) & 0xFFFFFFFFFFFFFFFF
    message_bytes += b'\x80'
    while (len(message_bytes) * 8) % 512 != 448:
        message_bytes += b'\x00'
    message_bytes += struct.pack('<Q', msg_len_bits)

    # Розбиття на 512-бітові блоки
    for chunk_start in range(0, len(message_bytes), 64):
        chunk = message_bytes[chunk_start:chunk_start+64]
        M = list(struct.unpack('<16I', chunk))
        a, b, c, d = A, B, C, D

        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3*i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7*i) % 16

            f = (f + a + T[i] + M[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + left_rotate(f, S[i])) & 0xFFFFFFFF

        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    # hex
    return '{:08X}{:08X}{:08X}{:08X}'.format(A, B, C, D)


def md5_for_text(s: str):
    return md5_bytes(s.encode('utf-8'))

def md5_for_bytes_stream(fobj, chunk_size=CHUNK_SIZE):
    data = bytearray()
    try:
        fobj.seek(0)
    except Exception:
        pass
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            break
        data.extend(chunk)
    return md5_bytes(data)

def main_hash(request):
    context = {'kind': None, 'name': None, 'md5': None, 'verified': None, 'error': None}

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'hash_text':
            text = request.POST.get('text', '')
            context['kind'] = 'text'
            context['name'] = (text[:60] + '...') if len(text) > 60 else text or '(empty)'
            context['md5'] = md5_for_text(text)

        elif action == 'hash_file':
            f = request.FILES.get('file')
            if not f:
                context['error'] = 'No file uploaded'
            else:
                context['kind'] = 'file'
                context['name'] = f.name
                context['md5'] = md5_for_bytes_stream(f.file)

        elif action == 'verify':
            f = request.FILES.get('file')
            if not f:
                context['error'] = 'No file to verify uploaded'
            else:
                computed = md5_for_bytes_stream(f.file)
                expected_text = request.POST.get('expected', '').strip()
                expected = expected_text.upper() if expected_text else None

                if not expected:
                    hashfile = request.FILES.get('hashfile')
                    if hashfile:
                        content = hashfile.read().decode('utf-8', errors='ignore')
                        expected = content.strip().split()[0].upper() if content.strip() else None

                verified = None
                if expected:
                    expected_clean = ''.join(c for c in expected if c.isalnum()).upper()[:32]
                    verified = (computed == expected_clean)

                context.update({'kind': 'verify', 'name': f.name, 'md5': computed, 'verified': verified})

        elif action == 'download_md5':
            return download_md5(request)

    return render(request, 'lab2/lab2.html', context)

def download_md5(request):
    md5 = request.POST.get('md5', '').strip().upper()
    name = request.POST.get('name', 'hash')

    if not md5:
        return HttpResponse('No MD5 provided', status=400)

    filename_safe = os.path.basename(name)
    content = f"{md5}  {filename_safe}\n"

    bio = io.BytesIO(content.encode('utf-8'))
    bio.seek(0)

    return FileResponse(
        bio,
        as_attachment=True,
        filename=f"{filename_safe}.md5",
        content_type="text/plain"
    )
