from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify, send_file
import io
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Función para generar llaves RSA
def generar_llaves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_pem, public_key_pem

# Función para crear un hash del contenido del archivo
def create_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# Función para cargar las claves DH desde un archivo
def cargar_claves_dh(archivo_dh_data):
    contenido = archivo_dh_data
    aes_key = contenido[:16]
    iv = contenido[16:32]
    return aes_key, iv

# Función para cifrar un archivo
def encrypt(archivo_dh_data, archivo_a_cifrar_data):
    aes_key_bytes, iv_bytes = cargar_claves_dh(archivo_dh_data)

    cipher = Cipher(algorithms.AES(aes_key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = archivo_a_cifrar_data + b'\0' * (16 - len(archivo_a_cifrar_data) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

# Función para descifrar un archivo
def descifrar(archivo_cifrado_data, archivo_dh_data):
    aes_key_bytes, iv_bytes = cargar_claves_dh(archivo_dh_data)

    cipher = Cipher(algorithms.AES(aes_key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(archivo_cifrado_data) + decryptor.finalize()
    data = padded_data.rstrip(b'\0')
    return data

# Función para firmar un archivo
def sign_data(llave_privada_data, archivo_a_cifrar_data):
    private_key = serialization.load_pem_private_key(
        llave_privada_data,
        password=None,
        backend=default_backend()
    )
    digest = create_hash(archivo_a_cifrar_data)
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Endpoint para crear un hash de un archivo
@app.route('/create_hash', methods=['POST'])
def create_hash_endpoint():
    try:
        archivo = request.files['archivo']
        if not archivo:
            return jsonify({'error': 'No se proporcionó ningún archivo'}), 400

        data = archivo.read()
        digest = create_hash(data)
        return jsonify({'hash': digest.hex()})  # Devolver el hash en hexadecimal

    except Exception as e:
        app.logger.error(f"Error en create_hash_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

# Endpoint para leer un archivo y devolver su contenido
@app.route('/read_file', methods=['POST'])
def read_file_endpoint():
    try:
        archivo = request.files['archivo']
        if not archivo:
            return jsonify({'error': 'No se proporcionó ningún archivo'}), 400

        contenido = archivo.read()
        return jsonify({'contenido': contenido.decode('utf-8')})  # Ajusta la codificación si es necesario
    except Exception as e:
        app.logger.error(f"Error en read_file_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

# Endpoint para descifrar un archivo
@app.route('/descifrar', methods=['POST'])
def descifrar_endpoint():
    try:
        archivo_cifrado = request.files['archivo_cifrado']
        archivo_dh = request.files['archivo_dh']

        if not archivo_cifrado or not archivo_dh:
            return jsonify({'error': 'Faltan archivos necesarios'}), 400

        archivo_cifrado_data = archivo_cifrado.read()
        archivo_dh_data = archivo_dh.read()

        datos_descifrados = descifrar(archivo_cifrado_data, archivo_dh_data)

        return send_file(
            io.BytesIO(datos_descifrados),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='archivo_descifrado.txt'
        )

    except Exception as e:
        app.logger.error(f"Error en descifrar_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

# Endpoint para verificar la firma de un archivo
@app.route('/verificar', methods=['POST'])
def verificar_endpoint():
    try:
        archivo_firmado = request.files['archivo_firmado']
        llave_publica = request.files['llave_publica']

        if not archivo_firmado or not llave_publica:
            return jsonify({'error': 'Faltan archivos necesarios'}), 400

        archivo_firmado_data = archivo_firmado.read()
        llave_publica_data = llave_publica.read()

        # Extraer datos y firma del archivo firmado
        separator = b'\n-----BEGIN SIGNATURE-----\n'
        end_separator = b'\n-----END SIGNATURE-----\n'
        first_position = archivo_firmado_data.find(separator)
        second_position = archivo_firmado_data.find(end_separator)
        if first_position == -1 or second_position == -1:
            return jsonify({'error': 'Formato de archivo firmado inválido'}), 400

        encrypted_data = archivo_firmado_data[:first_position]
        signature = archivo_firmado_data[first_position + len(separator):second_position]

        es_valida = verificar(encrypted_data, signature, llave_publica_data)

        return jsonify({'verificacion': es_valida})

    except Exception as e:
        app.logger.error(f"Error en verificar_endpoint: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
