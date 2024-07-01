from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from flask import Flask,Blueprint, request, jsonify
from flask_cors import CORS

bp = Blueprint('dh_betito', __name__)

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Función para cargar los parámetros desde bytes
def load_parameters(param_bytes):
    parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())
    return parameters

# Función para generar la clave privada y pública
def generate_private_public_key(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Función para serializar la clave pública
def serialize_public_key(public_key):
    public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key_bytes

# Función para cargar la clave pública desde bytes
def load_public_key(public_key_bytes):
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
    return public_key

# Función para derivar la clave compartida
def derive_aes_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    # Derivar una clave AES válida utilizando HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Longitud de la clave AES (256 bits)
        salt=None,
        info=b'aes key derivation',
        backend=default_backend()
    )
    aes_key = hkdf.derive(shared_key)
    return aes_key

@bp.route('/dh_exchange', methods=['POST'])
def dh_exchange_endpoint():
    # Obtener los archivos PEM de la solicitud
    parametros_dh_file = request.files['parametros_dh']
    alicia_public_key_file = request.files['alicia_public_key']

    # Leer el contenido de los archivos
    parametros_dh_pem = parametros_dh_file.read()
    alicia_public_key_pem = alicia_public_key_file.read()

    # Cargar los parámetros DH y la clave pública de Alicia
    alicia_public_key = load_public_key(alicia_public_key_pem)
    betito_parameters = load_parameters(parametros_dh_pem)

    # Betito genera su clave privada y pública
    betito_private_key, betito_public_key = generate_private_public_key(betito_parameters)

    # Betito deriva la clave compartida y la convierte en una clave AES
    betito_aes_key = derive_aes_key(betito_private_key, alicia_public_key)

    # Construir la respuesta JSON
    return jsonify({
        'betito_public_key': betito_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        'betito_private_key': betito_private_key.private_bytes(  # <-- ¡Nuevo!
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8'),
        'aes_key': betito_aes_key.hex()
    })

if __name__ == '__main__':
    app.run(debug=True)
