import os
from django.shortcuts import render
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

FILES_DIR = r"information_protection\lab5\lab5"


def digital_signature_tool(request):
    output_message = None
    generated_signature = None
    validation_status = None

    priv_key_location = os.path.join(FILES_DIR, "private_dss.pem")
    pub_key_location = os.path.join(FILES_DIR, "public_dss.pem")
    os.makedirs(FILES_DIR, exist_ok=True)

    if request.method == "POST":
        requested_action = request.POST.get("action")
        input_text = request.POST.get("text_input")
        uploaded_file = request.FILES.get("file_input")
        provided_signature = request.POST.get("signature_input")

        directory_path = request.POST.get("keys_path", "").strip()
        if not directory_path:
            directory_path = FILES_DIR
        os.makedirs(directory_path, exist_ok=True)

        priv_key_location = os.path.join(directory_path, "private_dss.pem")
        pub_key_location = os.path.join(directory_path, "public_dss.pem")

        if requested_action == "generate_keys":
            dsa_key = DSA.generate(2048)
            private_component = dsa_key.export_key()
            public_component = dsa_key.publickey().export_key()

            with open(priv_key_location, "wb") as key_file:
                key_file.write(private_component)
            with open(pub_key_location, "wb") as key_file:
                key_file.write(public_component)

            output_message = f"Ключі DSS успішно згенеровані і збережені в {directory_path}."

        elif requested_action == "sign":
            if not os.path.exists(priv_key_location):
                output_message = "Спершу згенеруйте ключі!"
            else:
                with open(priv_key_location, "rb") as key_file:
                    private_dsa_key = DSA.import_key(key_file.read())

                signature_generator = DSS.new(private_dsa_key, "fips-186-3")

                if input_text:
                    hash_obj = SHA256.new(input_text.encode("utf-8"))
                elif uploaded_file:
                    file_bytes = bytearray()
                    for chunk in uploaded_file.chunks():
                        file_bytes.extend(chunk)
                    hash_obj = SHA256.new(file_bytes)
                else:
                    output_message = "Нічого підписувати!"
                    hash_obj = None

                if hash_obj:
                    created_signature = signature_generator.sign(hash_obj)
                    generated_signature = created_signature.hex()
                    signature_file_name = "signature.hex"
                    with open(os.path.join(directory_path, signature_file_name), "w") as sig_file:
                        sig_file.write(generated_signature)
                    output_message = f"Цифровий підпис створено. Збережено як {signature_file_name} у {directory_path}"

        elif requested_action == "verify":
            if not os.path.exists(pub_key_location):
                output_message = "Спершу згенеруйте ключі!"
            else:
                with open(pub_key_location, "rb") as key_file:
                    public_dsa_key = DSA.import_key(key_file.read())

                signature_validator = DSS.new(public_dsa_key, "fips-186-3")

                if input_text:
                    hash_obj = SHA256.new(input_text.encode("utf-8"))
                elif uploaded_file:
                    file_bytes = bytearray()
                    for chunk in uploaded_file.chunks():
                        file_bytes.extend(chunk)
                    hash_obj = SHA256.new(file_bytes)
                else:
                    hash_obj = None

                if provided_signature:
                    try:
                        signature_bytes = bytes.fromhex(provided_signature)
                    except ValueError:
                        signature_bytes = None
                else:
                    signature_bytes = None

                if hash_obj and signature_bytes:
                    try:
                        signature_validator.verify(hash_obj, signature_bytes)
                        validation_status = "Підпис вірний"
                    except ValueError:
                        validation_status = "Підпис не вірний"

    return render(request, "lab5/dss_tool.html", {
        "result": output_message,
        "signature_hex": generated_signature,
        "verification_result": validation_status,
        "default_path": FILES_DIR
    })