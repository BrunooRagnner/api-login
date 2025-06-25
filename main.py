from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
import re

app = Flask(__name__)
CORS(app)  # Habilita CORS para todas as rotas

# Configurações
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sua-chave-secreta-aqui')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-jwt-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nintendo_burg.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

# Modelo de Usuário
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    telefone = db.Column(db.String(20), nullable=False)
    senha_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha)
    
    def check_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)

@app.route('/usuarios', methods=['POST', 'OPTIONS'])
def registrar_usuario():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    
    dados = request.get_json()
    
    # Validações
    if not dados or not dados.get('email') or not dados.get('senha'):
        return jsonify({'erro': 'Email e senha são obrigatórios'}), 400
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", dados['email']):
        return jsonify({'erro': 'Email inválido'}), 400
    
    if Usuario.query.filter_by(email=dados['email']).first():
        return jsonify({'erro': 'Email já cadastrado'}), 400
    
    usuario = Usuario(
        nome=dados.get('nome', ''),
        email=dados['email'],
        telefone=dados.get('telefone', ''),
        is_admin=dados.get('is_admin', False)
    )
    usuario.set_senha(dados['senha'])
    db.session.add(usuario)
    db.session.commit()
    
    return jsonify({
        'mensagem': 'Usuário registrado com sucesso',
        'usuario': {
            'id': usuario.id,
            'nome': usuario.nome,
            'email': usuario.email,
            'telefone': usuario.telefone,
            'is_admin': usuario.is_admin
        }
    }), 201

@app.route('/login', methods=['POST'])
def login():
    dados = request.get_json()
    
    if not dados or not dados.get('email') or not dados.get('senha'):
        return jsonify({'erro': 'Email e senha são obrigatórios'}), 400
    
    usuario = Usuario.query.filter_by(email=dados['email']).first()
    
    if not usuario or not usuario.check_senha(dados['senha']):
        return jsonify({'erro': 'Credenciais inválidas'}), 401
    
    token = create_access_token(identity=usuario.id)
    return jsonify({
        'mensagem': 'Login bem-sucedido',
        'token': token,
        'usuario': {
            'id': usuario.id,
            'nome': usuario.nome,
            'email': usuario.email,
            'telefone': usuario.telefone,
            'is_admin': usuario.is_admin
        }
    }), 200

@app.route('/perfil', methods=['GET'])
@jwt_required()
def perfil():
    usuario_id = get_jwt_identity()
    usuario = Usuario.query.get(usuario_id)
    
    if not usuario:
        return jsonify({'erro': 'Usuário não encontrado'}), 404
    
    return jsonify({
        'id': usuario.id,
        'nome': usuario.nome,
        'email': usuario.email,
        'telefone': usuario.telefone,
        'is_admin': usuario.is_admin
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
