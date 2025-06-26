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
    return html, 200, {'Content-Type': 'text/html'}
