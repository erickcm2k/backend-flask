from flask import Flask, request, send_file, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
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

if __name__ == '__main__':
    app.run(debug=True)
