from flask import Flask
from blueprints.DH_Alicia import bp as DH_Alicia_bp
from blueprints.DH_Betito import bp as DH_Betito_bp
from blueprints.hibrid_Alicia import bp as Hibrid_Alicia_bp
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
# Registrar los blueprints
app.register_blueprint(DH_Alicia_bp, url_prefix='/DH_Alicia')
app.register_blueprint(DH_Betito_bp, url_prefix='/DH_Betito')
app.register_blueprint(Hibrid_Alicia_bp, url_prefix='/Hibrid_Alicia')

if __name__ == '__main__':
    app.run(debug=True)
