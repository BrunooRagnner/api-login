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
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'manf123')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret')

# Caminho para SQLite (caso DATABASE_URL não esteja definido)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    f'sqlite:///{os.path.join(basedir, "app.db")}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialização de extensões
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

# ✅ Criação do banco (funciona no Render)
with app.app_context():
    db.create_all()

# Rotas

@app.route('/')
def index():
    html = '''
    <!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Documentação da API - Flask JWT</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
            background-color: #f9f9f9;
            color: #222;
        }
        h1, h2, h3 {
            color: #00539C;
        }
        code {
            background-color: #eee;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }
        pre {
            background-color: #eee;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .endpoint {
            background-color: #d0e4f5;
            border-left: 5px solid #00539C;
            padding: 10px;
            margin-bottom: 20px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 30px;
        }
        th, td {
            border: 1px solid #ccc;
            padding: 8px 12px;
            text-align: left;
        }
        th {
            background-color: #00539C;
            color: white;
        }
    </style>
</head>
<body>
    <h1>Documentação da API - Flask JWT</h1>
    <p>Esta API oferece funcionalidades de registro, login e acesso a dados protegidos de usuários usando JWT.</p>

    <h2>Base URL</h2>
    <p><code>/api</code></p>

    <div class="endpoint">
        <h3>1. Registro de Usuário</h3>
        <p><strong>POST /api/register</strong></p>
        <p>Registra um novo usuário.</p>

        <h4>Headers</h4>
        <ul>
            <li><code>Content-Type: application/json</code></li>
        </ul>

        <h4>Corpo da requisição (JSON)</h4>
        <table>
            <thead>
                <tr>
                    <th>Campo</th>
                    <th>Tipo</th>
                    <th>Descrição</th>
                    <th>Obrigatório</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>nome</td><td>string</td><td>Nome completo do usuário</td><td>Sim</td></tr>
                <tr><td>email</td><td>string</td><td>Email único do usuário</td><td>Sim</td></tr>
                <tr><td>telefone</td><td>string</td><td>Telefone do usuário</td><td>Sim</td></tr>
                <tr><td>password</td><td>string</td><td>Senha (mínimo 6 caracteres)</td><td>Sim</td></tr>
                <tr><td>confirmar_senha</td><td>string</td><td>Confirmação da senha</td><td>Sim</td></tr>
            </tbody>
        </table>

        <h4>Respostas</h4>
        <pre><code>201 Created
{
  "message": "Usuário registrado com sucesso",
  "access_token": "token_jwt_aqui",
  "user": {
    "id": 1,
    "nome": "Nome Completo",
    "email": "email@exemplo.com",
    "telefone": "123456789"
  }
}
        </code></pre>

        <pre><code>400 Bad Request
{
  "error": "Mensagem de erro específica"
}
        </code></pre>
    </div>

    <div class="endpoint">
        <h3>2. Login</h3>
        <p><strong>POST /api/login</strong></p>
        <p>Autentica usuário e retorna um token JWT.</p>

        <h4>Headers</h4>
        <ul>
            <li><code>Content-Type: application/json</code></li>
        </ul>

        <h4>Corpo da requisição (JSON)</h4>
        <table>
            <thead>
                <tr>
                    <th>Campo</th>
                    <th>Tipo</th>
                    <th>Descrição</th>
                    <th>Obrigatório</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>email</td><td>string</td><td>Email do usuário</td><td>Sim</td></tr>
                <tr><td>password</td><td>string</td><td>Senha do usuário</td><td>Sim</td></tr>
            </tbody>
        </table>

        <h4>Respostas</h4>
        <pre><code>200 OK
{
  "access_token": "token_jwt_aqui",
  "user": {
    "id": 1,
    "nome": "Nome Completo",
    "email": "email@exemplo.com",
    "telefone": "123456789"
  }
}
        </code></pre>

        <pre><code>400 Bad Request / 401 Unauthorized
{
  "error": "Mensagem de erro específica"
}
        </code></pre>
    </div>

    <div class="endpoint">
        <h3>3. Rota Protegida - Dados do Usuário</h3>
        <p><strong>GET /api/protected</strong></p>
        <p>Retorna os dados do usuário autenticado (token JWT obrigatório).</p>

        <h4>Headers</h4>
        <ul>
            <li><code>Authorization: Bearer &lt;token_jwt&gt;</code></li>
        </ul>

        <h4>Resposta</h4>
        <pre><code>200 OK
{
  "id": 1,
  "nome": "Nome Completo",
  "email": "email@exemplo.com",
  "telefone": "123456789"
}
        </code></pre>

        <pre><code>404 Not Found
{
  "error": "Usuário não encontrado"
}
        </code></pre>
    </div>

    <h2>Detalhes adicionais</h2>
    <ul>
        <li><strong>Cross-Origin Resource Sharing (CORS):</strong> Permitido para todas origens na rota <code>/api/*</code>.</li>
        <li><strong>Segurança:</strong> As senhas são armazenadas de forma segura usando hashing com Werkzeug.</li>
        <li><strong>Autenticação:</strong> Usada via JWT (JSON Web Tokens), garantindo que rotas protegidas só sejam acessadas por usuários autenticados.</li>
    </ul>

    <h2>Executar localmente</h2>
    <p>Para rodar a API localmente, execute:</p>
    <pre><code>python nome_do_arquivo.py</code></pre>

</body>
</html>

    
    
    
    '''
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
