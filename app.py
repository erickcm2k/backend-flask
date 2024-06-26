from flask import Flask, request, send_file, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def generate_key_iv():
    key = os.urandom(16)
    iv = os.urandom(16)
    return key, iv

# Funciones para CBC

def encrypt_image_cbc(key, iv, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Read the 54-byte header
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_cCBC.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Write the header without encryption
        f.write(iv + ciphertext)
    return output_file

def decrypt_image_cbc(key, iv, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Read the 54-byte header
        iv_ciphertext = f.read()

    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    try:
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError as e:
        raise ValueError("Error in unpadding: data may be corrupted or key/iv is incorrect") from e

    output_file = os.path.splitext(input_file)[0] + "_dCBC.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Write the header without encryption
        f.write(unpadded_data)
    return output_file

# Funciones para CFB

def encrypt_image_cfb(key, iv, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_cCFB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(iv + ciphertext)
    return output_file        

def decrypt_image_cfb(key, iv, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        iv_ciphertext = f.read()

    iv = iv_ciphertext[:len(iv)]
    ciphertext = iv_ciphertext[len(iv):]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_dCFB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(decrypted_data)
    return output_file        

# Funciones para ECB

def encrypt_image_ecb(key, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_cECB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(ciphertext)
    return output_file

def decrypt_image_ecb(key, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    output_file = os.path.splitext(input_file)[0] + "_dECB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(unpadded_data)
    return output_file

# Funciones para OFB

def encrypt_image_ofb(key, iv, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_cOFB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(iv + ciphertext)
    return output_file

def decrypt_image_ofb(key, iv, input_file):
    with open(input_file, 'rb') as f:
        header = f.read(54)  # Lee la cabecera de 54 bytes
        iv_ciphertext = f.read()

    iv = iv_ciphertext[:len(iv)]
    ciphertext = iv_ciphertext[len(iv):]

    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    output_file = os.path.splitext(input_file)[0] + "_dOFB.bmp"
    with open(output_file, 'wb') as f:
        f.write(header)  # Escribe la cabecera sin cifrar
        f.write(decrypted_data)
    return output_file

# Generación de llave y vector de inicialización

@app.route('/generate_key_iv', methods=['GET'])
def generate_key_iv_endpoint():
    key, iv = generate_key_iv()
    return jsonify({"key": key.hex(), "iv": iv.hex()})

# Endpoints para CBC

@app.route('/CBC/encrypt', methods=['POST'])
def encrypt_image_CBC_endpoint():
    key = bytes.fromhex(request.form['key'])
    print('key')
    print(key)
    iv = bytes.fromhex(request.form['iv'])
    print('iv')
    print(iv)
    file = request.files['image']
    input_file = "input_image.bmp"
    file.save(input_file)
    
    encrypted_file = encrypt_image_cbc(key, iv, input_file)
    
    return send_file(encrypted_file, mimetype='image/bmp')

@app.route('/CBC/decrypt', methods=['POST'])
def decrypt_image_CBC_endpoint():
    key = bytes.fromhex(request.form['key'])
    print('key')
    print(key)
    iv = bytes.fromhex(request.form['iv'])
    print('iv')
    print(iv)
    file = request.files['image']
    input_file = "input_image_cCBC.bmp"
    file.save(input_file)
    
    decrypted_file = decrypt_image_cbc(key,iv, input_file)    
    return send_file(decrypted_file, mimetype='image/bmp')

# Endpoints para CFB

@app.route('/CFB/encrypt', methods=['POST'])
def encrypt_image_CFB_endpoint():
    key = bytes.fromhex(request.form['key'])
    print('key')
    print(key)
    iv = bytes.fromhex(request.form['iv'])
    print('iv')
    print(iv)
    file = request.files['image']
    input_file = "input_image.bmp"
    file.save(input_file)
    
    encrypted_file = encrypt_image_cfb(key, iv, input_file)
    
    return send_file(encrypted_file, mimetype='image/bmp')

@app.route('/CFB/decrypt', methods=['POST'])
def decrypt_image_cfb_endpoint():
    key = bytes.fromhex(request.form['key'])
    print('key')
    print(key)
    iv = bytes.fromhex(request.form['iv'])
    print('iv')
    print(iv)
    file = request.files['image']
    input_file = "input_image_cCBC.bmp"
    file.save(input_file)
    
    decrypted_file = decrypt_image_cfb(key,iv, input_file)    
    return send_file(decrypted_file, mimetype='image/bmp')

# Endpoints para ECB

@app.route('/ECB/encrypt', methods=['POST'])
def encrypt_image_ECB_endpoint():
    key = bytes.fromhex(request.form['key'])
    file = request.files['image']
    input_file = "input_image.bmp"
    file.save(input_file)
    
    encrypted_file = encrypt_image_ecb(key, input_file)
    
    return send_file(encrypted_file, mimetype='image/bmp')

@app.route('/ECB/decrypt', methods=['POST'])
def decrypt_image_ECB_endpoint():
    key = bytes.fromhex(request.form['key'])
    file = request.files['image']
    input_file = "input_image_cCBC.bmp"
    file.save(input_file)
    
    decrypted_file = decrypt_image_ecb(key, input_file)    
    return send_file(decrypted_file, mimetype='image/bmp')

# Endpoints para OFB

@app.route('/OFB/encrypt', methods=['POST'])
def encrypt_image_OFB_endpoint():
    key = bytes.fromhex(request.form['key'])
    print('key')
    print(key)
    iv = bytes.fromhex(request.form['iv'])
    print('iv')
    print(iv)
    file = request.files['image']
    input_file = "input_image.bmp"
    file.save(input_file)
    
    encrypted_file = encrypt_image_ofb(key, iv, input_file)
    
    return send_file(encrypted_file, mimetype='image/bmp')

@app.route('/OFB/decrypt', methods=['POST'])
def decrypt_image_OFB_endpoint():
    key = bytes.fromhex(request.form['key'])
    print('key')
    print(key)
    iv = bytes.fromhex(request.form['iv'])
    print('iv')
    print(iv)
    file = request.files['image']
    input_file = "input_image_cCBC.bmp"
    file.save(input_file)
    
    decrypted_file = decrypt_image_ofb(key,iv, input_file)    
    return send_file(decrypted_file, mimetype='image/bmp')


# Para la parte de RSA

# Funciones para RSA

def rsa_decrypt_fn(llave_privada, texto_cifrado):
  
    try:
        # Cargar la clave privada desde el string PEM
        private_key = serialization.load_pem_private_key(
            llave_privada.encode('utf-8'),
            password=None,  # Si la clave privada tiene contraseña, proporciona aquí
            backend=default_backend()
        )

        # Decodificar el texto cifrado desde base64
        encrypted_data = base64.b64decode(texto_cifrado)

        # Obtener la longitud de la clave AES cifrada
        aes_key_length = int.from_bytes(encrypted_data[:4], 'big')

        # Separar los datos cifrados de la clave AES y el IV
        encrypted_aes_key = encrypted_data[4 : 4 + aes_key_length]
        encrypted_iv = encrypted_data[4 + aes_key_length :]

        # Descifrar la clave AES usando la clave privada RSA
        aes_key_bytes = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Descifrar el IV usando la clave privada RSA
        iv_bytes = private_key.decrypt(
            encrypted_iv,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Convertir la clave AES y el IV a base64
        aes_key_base64 = base64.b64encode(aes_key_bytes).decode('utf-8')
        iv_base64 = base64.b64encode(iv_bytes).decode('utf-8')

        # Retornar la clave AES y el IV como texto, separados por un salto de línea
        decrypted_text = aes_key_base64 + '\n' + iv_base64
        return decrypted_text

    except Exception as e:
        print(f"Error durante el descifrado: {e}")
        return None

def rsa_encrypt_fn(llave_publica, archivo_a_cifrar):
    # Leer la clave pública desde el archivo
        
    public_key = serialization.load_pem_public_key(
        llave_publica.encode('utf-8'),  # Codificar el string a bytes
        backend=default_backend()
    )        

    # Leer el archivo que contiene la clave AES y el IV
    lines = archivo_a_cifrar.splitlines()
    aes_key = lines[0].strip()
    iv = lines[1].strip()

    # Convertir la clave AES y el IV a bytes
    aes_key_bytes = base64.b64decode(aes_key)
    iv_bytes = base64.b64decode(iv)

    # Cifrar la clave AES y el IV usando la clave pública RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_iv = public_key.encrypt(
        iv_bytes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Guardar la longitud de la clave AES cifrada
    aes_key_length = len(encrypted_aes_key)

    # Guardar el texto cifrado en un archivo .txt
    encrypted_data = aes_key_length.to_bytes(4, 'big') + encrypted_aes_key + encrypted_iv
    encrypted_text = base64.b64encode(encrypted_data).decode('utf-8')

    print("Cifrado completado")
    return encrypted_text  # Retornar el texto cifrado en base64

def rsa_get_keys_fn():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serializar las claves a formato PEM (texto)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Opcional: agregar contraseña
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode('utf-8'), public_pem.decode('utf-8')  # Decodificar a str

@app.route('/RSA/decrypt', methods=['POST'])
def rsa_decrypt():
    public_key_file = request.form['privateKey']
    texto_a_cifrar = request.form['content']

    # Llamar a la función rsa_encrypt_fn
    ruta_archivo_cifrado = rsa_decrypt_fn(public_key_file, texto_a_cifrar)

    # Retornar la ruta del archivo cifrado (o su contenido)
    return ruta_archivo_cifrado

@app.route('/RSA/encrypt', methods=['POST'])
def rsa_encrypt():
    public_key_file = request.form['publicKey']
    texto_a_cifrar = request.form['content']

    # Llamar a la función rsa_encrypt_fn
    ruta_archivo_cifrado = rsa_encrypt_fn(public_key_file, texto_a_cifrar)

    # Retornar la ruta del archivo cifrado (o su contenido)
    return ruta_archivo_cifrado
    
@app.route('/RSA/getKeys', methods=['GET'])
def rsa_get_keys():
    private_key_text, public_key_text = rsa_get_keys_fn()
    return jsonify({
        "private_key": private_key_text, 
        "public_key": public_key_text
    })


if __name__ == '__main__':
    app.run(debug=True)
