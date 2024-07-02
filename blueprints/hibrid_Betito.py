from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask,Blueprint, request,send_file, jsonify
from cryptography.exceptions import InvalidSignature
from flask_cors import CORS
import io
app = Flask(__name__)
CORS(app)

bp = Blueprint('hibrid_betito', __name__)

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
    print('bien hasta aquí')
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

def verificar(data, signature, llave_publica):
    """Verifica la firma digital utilizando la clave pública proporcionada."""
    try:
        public_key = serialization.load_pem_public_key(
            llave_publica.read(), 
            backend=default_backend()
        )

        public_key.verify(
            signature,
            create_hash(data),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # La firma es válida
    except InvalidSignature:
        return False  # La firma no es válida

@bp.route('/verificar', methods=['POST'])
def verificar_endpoint():
    """Endpoint Flask para verificar la firma digital de un archivo cifrado con AES."""
    try:
        # Obtener los archivos del formulario
        archivo_firmado = request.files['archivo_firmado'].read()  
        llave_publica = request.files['llave_publica']
        archivo_dh = request.files['archivo_dh'].read()  
        archivo_descifrado = request.files['archivo_descifrado'].read() 

        if not all([archivo_firmado, llave_publica, archivo_dh, archivo_descifrado]):
            return jsonify({"error": "Faltan archivos necesarios"}), 400

        # Cargar la clave AES y el IV
        aes_key, iv = cargar_claves_dh(archivo_dh)

        # Separar datos y firma (asumiendo formato PKCS#7)
        separator = b'\n-----BEGIN SIGNATURE-----\n'
        end_separator = b'\n-----END SIGNATURE-----\n'
        first_position = archivo_firmado.find(separator)
        second_position = archivo_firmado.find(end_separator)

        if first_position == -1 or second_position == -1:
            return jsonify({"error": "Formato de archivo firmado inválido"}), 400

        #encrypted_data = archivo_combinado[:first_position]
        signature = archivo_firmado[first_position + len(separator):second_position]

        # Verificar la firma con los datos del archivo descifrado (bytes)
        es_valida = verificar(archivo_descifrado, signature, llave_publica)

        return jsonify({"verificacion": es_valida})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route('/descifrar', methods=['POST'])
def descifrar_endpoint():
    try:
        archivo_dh = request.files['archivo_dh']
        archivo_cifrado = request.files['archivo_cifrado']

        if not archivo_cifrado or not archivo_dh:
            return jsonify({'error': 'Faltan archivos necesarios'}), 400

        # Apertura de archivos en modo binario (clave para archivos no texto)
        with archivo_cifrado.stream as f_cifrado, archivo_dh.stream as f_dh:
            archivo_cifrado_data = f_cifrado.read()
            archivo_dh_data = f_dh.read()

        datos_descifrados = descifrar(archivo_cifrado_data, archivo_dh_data)

        # Uso de BytesIO para enviar datos binarios
        return send_file(
            io.BytesIO(datos_descifrados),
            mimetype='application/octet-stream',  # Tipo genérico para binarios
            as_attachment=True,
            download_name='archivo_descifrado.bin'  # Extensión .bin más adecuada
        )

    except Exception as e:
        app.logger.error(f"Error en descifrar_endpoint: {e}")
        return jsonify({'error': 'Error interno en el servidor'}), 500  # Mensaje genérico para seguridad


if __name__ == '__main__':
    app.run(debug=True)
