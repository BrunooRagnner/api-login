from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configurações
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sua-chave-secreta')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret')

# Caminho para banco local SQLite ou DATABASE_URL se existir
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    f'sqlite:///{os.path.join(basedir, "app.db")}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensões
jwt = JWTManager(app)
db = SQLAlchemy(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20))
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Criar tabelas automaticamente no primeiro acesso
@app.before_first_request
def create_tables():
    db.create_all()

# Rotas
@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    required_fields = ['nome', 'email', 'telefone', 'password', 'confirmar_senha']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    if data['password'] != data['confirmar_senha']:
        return jsonify({"error": "As senhas não coincidem"}), 400

    if len(data['password']) < 6:
        return jsonify({"error": "Senha deve ter pelo menos 6 caracteres"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email já cadastrado"}), 400

    user = User(
        nome=data['nome'],
        email=data['email'],
        telefone=data['telefone']
    )
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=user.email)
    return jsonify({
        "message": "Usuário registrado com sucesso",
        "access_token": access_token,
        "user": {
            "id": user.id,
            "nome": user.nome,
            "email": user.email,
            "telefone": user.telefone
        }
    }), 201

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email e senha são obrigatórios"}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({"error": "Email ou senha incorretos"}), 401

    access_token = create_access_token(identity=user.email)
    return jsonify({
        "access_token": access_token,
        "user": {
            "id": user.id,
            "nome": user.nome,
            "email": user.email,
            "telefone": user.telefone
        }
    }), 200

@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({"error": "Usuário não encontrado"}), 404

    return jsonify({
        "id": user.id,
        "nome": user.nome,
        "email": user.email,
        "telefone": user.telefone
    }), 200

# Rodar localmente (opcional)
if __name__ == '__main__':
    app.run(debug=True)
