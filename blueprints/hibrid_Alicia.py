from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask,Blueprint, send_file, request, jsonify
import io
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

bp = Blueprint('hibrid_alicia', __name__)

#genera llaves de RSA
def generar_llaves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serializar y guardar las llaves en archivos .key
    with open("alicia_private_rsa.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("alicia_public_rsa.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return "alicia_private_rsa.pem", "alicia_public_rsa.pem"

def create_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def cargar_claves_dh(archivo_dh):
    with open(archivo_dh, "rb") as f:
        contenido = f.read()
    # Tomar los primeros 32 caracteres como la clave y los siguientes 16 como el IV
    aes_key = contenido[:16]
    iv = contenido[16:32]
    return aes_key, iv

def encrypt(archivo_dh, archivo_a_cifrar, archivo_salida):
    aes_key_bytes, iv_bytes = cargar_claves_dh(archivo_dh)

    # Cargar el archivo a cifrar
    with open(archivo_a_cifrar, "rb") as f:
        data = f.read()

    # Cifrar el archivo con AES
    cipher = Cipher(algorithms.AES(aes_key_bytes), modes.CBC(iv_bytes), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b'\0' * (16 - len(data) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Guardar el archivo cifrado
    with open(archivo_salida, "wb") as f:
        f.write(encrypted_data)
    
    print("Archivo cifrado guardado en:", archivo_salida)
    return archivo_salida

def generar_hash_y_firmar(archivo_a_cifrar, archivo_cifrado, llave_privada):
    # Calcular el hash del archivo
    with open(archivo_a_cifrar, "rb") as f:
        data = f.read()
        digest = create_hash(data)

    # Leer la clave privada desde el archivo
    with open(llave_privada, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(
            priv_file.read(),
            password=None,
            backend=default_backend()
        )

    signature = sign_data (private_key, digest)

    with open(archivo_cifrado, "rb") as f:
        data_encrypted = f.read()
        # Guardar el archivo cifrado y la firma en un archivo combinado
        archivo_firmado = archivo_cifrado + '.signed'
        with open(archivo_firmado, 'wb') as combined_file:
            combined_file.write(data_encrypted + b'\n-----BEGIN SIGNATURE-----\n' + signature + b'\n-----END SIGNATURE-----\n')
        print(f"El archivo ha sido firmado y se ha guardado en {archivo_firmado}")
        print(f"Comparte 'alicia_public_rsa.pem'")

# Endpoint para generar llaves RSA
@bp.route('/generar_llaves', methods=['GET'])
def generar_llaves_endpoint():
    private_key_file, public_key_file = generar_llaves()

    # Leer los archivos generados
    with open(private_key_file, 'rb') as f:
        private_key_data = f.read()
    with open(public_key_file, 'rb') as f:
        public_key_data = f.read()

    # Construye la respuesta JSON
    return jsonify({
        'private_key': private_key_data.decode('utf-8'),
        'public_key': public_key_data.decode('utf-8')
    })

# Endpoint para cifrar un archivo
from flask import send_file, request
import io

@bp.route('/encrypt', methods=['POST'])
def encrypt_endpoint():
    try:
        archivo_dh = request.files['archivo_dh']
        archivo_a_cifrar = request.files['archivo_a_cifrar']

        # Guardar los archivos temporalmente (puedes optimizar esto si prefieres)
        archivo_dh.save('temp_archivo_dh')
        archivo_a_cifrar.save('temp_archivo_a_cifrar')

        # Cifrar el archivo
        archivo_cifrado = encrypt('temp_archivo_dh', 'temp_archivo_a_cifrar', 'temp_archivo_cifrado.bin')

        # Enviar el archivo cifrado como respuesta
        return send_file(
            archivo_cifrado,
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='archivo_cifrado.bin'
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        # Eliminar los archivos temporales después de usarlos
        import os
        os.remove('temp_archivo_dh')
        os.remove('temp_archivo_a_cifrar')
        os.remove('temp_archivo_cifrado.bin')


# Endpoint para firmar un archivo cifrado
@bp.route('/sign_data', methods=['POST'])
def sign_data_endpoint():
    try:
        # Obtener los archivos de la solicitud
        archivo_a_cifrar = request.files['archivo_a_cifrar']
        archivo_cifrado = request.files['archivo_cifrado']
        llave_privada_file = request.files['llave_privada']

        # Validar que se recibieron los archivos necesarios
        if not archivo_a_cifrar or not archivo_cifrado or not llave_privada_file:
            return jsonify({'error': 'Faltan archivos necesarios'}), 400

        # Leer el contenido de los archivos directamente
        data = archivo_a_cifrar.read()
        data_encrypted = archivo_cifrado.read()
        private_key_data = llave_privada_file.read()

        # Calcular el hash y firmar directamente en memoria
        digest = create_hash(data)

        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None,
            backend=default_backend()
        )

        signature = sign_data(private_key, digest)

        # Combinar el archivo cifrado y la firma en memoria
        archivo_firmado_data = data_encrypted + b'\n-----BEGIN SIGNATURE-----\n' + signature + b'\n-----END SIGNATURE-----\n'

        # Devolver el archivo firmado sin guardarlo en disco
        return send_file(
            io.BytesIO(archivo_firmado_data),  # Crear un objeto BytesIO para enviar los datos
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name='archivo_firmado.signed'
        )

    except Exception as e:
        app.logger.error(f"Error en sign_data_endpoint: {e}")  
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)