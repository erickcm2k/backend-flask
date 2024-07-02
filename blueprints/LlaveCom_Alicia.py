from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from flask import Flask, Blueprint,request, jsonify
from flask_cors import CORS

bp = Blueprint('llavecom_alicia', __name__)

app = Flask(__name__)
CORS(app, supports_credentials=True)
# Función para cargar la clave privada desde bytes
def load_private_key(private_key_bytes):
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
    return private_key

# Función para cargar la clave pública desde bytes
def load_public_key(public_key_bytes):
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
    return public_key

# Función para derivar la clave compartida y convertirla en una clave AES
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

def obten_secreto(input_private_key_dh, input_public_key_dh, output_aes_key):
    # Alicia carga su clave privada generada previamente
    with open(input_private_key_dh, "rb") as f:
        alicia_private_key_bytes = f.read()
    alicia_private_key = load_private_key(alicia_private_key_bytes)

    # Alicia carga la clave pública de Betito
    with open(input_public_key_dh, "rb") as f:
        betito_public_key_bytes = f.read()
    betito_public_key = load_public_key(betito_public_key_bytes)

    # Alicia deriva la clave compartida y la convierte en una clave AES
    alicia_aes_key = derive_aes_key(alicia_private_key, betito_public_key)
    #print(f"Clave AES derivada por Alicia: {alicia_aes_key.hex()}")

    # Guardar la clave AES en un archivo
    with open(output_aes_key, "wb") as f:
        f.write(alicia_aes_key)

# obten_secreto(entrada_private_key_dh, entrada_public_key_dh, salida_aes)
# print(f"Se generó y guardó llave aes en : {salida_aes}")

@bp.route('/obten_secreto', methods=['POST'])
def obten_secreto_endpoint():
    # Obtener los archivos PEM de la solicitud
    alicia_private_key_file = request.files['alicia_private_key']
    betito_public_key_file = request.files['betito_public_key']

    # Leer el contenido de los archivos
    alicia_private_key_pem = alicia_private_key_file.read()
    betito_public_key_pem = betito_public_key_file.read()

    # Cargar la clave privada de Alicia y la clave pública de Betito desde PEM
    alicia_private_key = load_private_key(alicia_private_key_pem)
    betito_public_key = load_public_key(betito_public_key_pem)

    # Alicia deriva la clave compartida y la convierte en una clave AES
    alicia_aes_key = derive_aes_key(alicia_private_key, betito_public_key)

    # Construir la respuesta JSON solo con la clave AES de Alicia
    return jsonify({
        'aes_key': alicia_aes_key.hex()  # Convertir a hexadecimal para enviar
    })

if __name__ == '__main__':
    app.run(debug=True)

