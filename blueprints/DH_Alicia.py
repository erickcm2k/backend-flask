from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from flask import Flask, jsonify, Blueprint, send_file
from flask_cors import CORS  # Importar Flask-CORS
import io

bp = Blueprint('dh_alicia', __name__)

app = Flask(__name__)
CORS(app)  # Habilitar CORS para toda la aplicación

entrada = "poema.txt"
salida_public_key = "alicia_public_key_dh.pem"
salida_param = "parametros_dh.pem"
salida_private_key = "alicia_private_key_dh.pem"

# Función para generar los parámetros DH
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

# Función para serializar los parámetros
def serialize_parameters(parameters):
    param_bytes = parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3)
    return param_bytes

# Función para generar la clave privada y pública
def generate_private_public_key(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Función para serializar la clave pública
def serialize_public_key(public_key):
    public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return public_key_bytes

def genera_params_key_dh(output_public_key, output_private_key,output_param):
    # Alicia genera los parámetros DH
    parameters = generate_dh_parameters()
    param_bytes = serialize_parameters(parameters)
    
    # Guardar los parámetros en un archivo para compartir con Betito
    with open(output_param, "wb") as f:
        f.write(param_bytes)

    # Alicia genera su clave privada y pública
    alicia_private_key, alicia_public_key = generate_private_public_key(parameters)
    alicia_public_key_bytes = serialize_public_key(alicia_public_key)

    # Guardar la clave pública en un archivo para compartir con Betito
    with open(output_public_key, "wb") as f:
        f.write(alicia_public_key_bytes)

    # Guardar la clave privada en un archivo para uso futuro
    with open(output_private_key, "wb") as f:
        f.write(alicia_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

# genera_params_key_dh(salida_public_key, salida_private_key, salida_param)
# print("Parámetros DH y clave pública de Alicia generados y guardados.")
# print(f"Comparte {salida_param} y {salida_public_key} con Betito.")


@bp.route('/generate_dh_params', methods=['GET'])
def generate_dh_params_endpoint():
    output_public_key = "alicia_public_key_dh.pem"
    output_param = "parametros_dh.pem"
    output_private_key = "alicia_private_key_dh.pem" # Ruta de la clave privada

    # Genera las claves y parámetros
    genera_params_key_dh(output_public_key, output_private_key, output_param)

    # Lee los archivos generados
    with open(output_public_key, 'rb') as f:
        public_key_data = f.read()
    with open(output_param, 'rb') as f:
        param_data = f.read()
    with open(output_private_key, 'rb') as f:  # Lee la clave privada
        private_key_data = f.read()

    # Construye la respuesta JSON
    return jsonify({
        'public_key': public_key_data.decode('utf-8'),
        'dh_params': param_data.decode('utf-8'),
        'private_key': private_key_data.decode('utf-8')  # Incluye la clave privada
    })

if __name__ == '__main__':
    app.run(debug=True)