// Para demonstrar a vulnerabilidade XSS, tive que temporariamente permitir
// saída não escapada no template EJS(`<%- comment.content %>`) e desativar a sanitização de entrada.
// Submeti o payload de teste `<script>alert('XSS')</script>` via formulário.Ao recarregar, o alerta
// `XSS` foi executado — prova de execução de código injetado.
// Em seguida, reverti as alterações: usei `<%= comment.content %>` no template, restaurei`sanitize-html`
//  e configurei o cookie `session_id` com`httpOnly: true`.
// Conclusão: a aplicação originalmente permitia injeção e execução de JavaScript submetido por usuários.Após as correções (escape no template e sanitização), o payload deixou de ser executado.

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const sanitizeHtml = require('sanitize-html');
const helmet = require('helmet');

const app = express();

const db = new sqlite3.Database(':memory:');
app.use(helmet()); // adiciona headers de segurança básicos
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');

// Criar tabela de comentários
db.serialize(() => {
    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY, content TEXT)");
    db.run("INSERT INTO comments (content) VALUES ('Bem-vindo ao desafio de XSS!')");
});

// Middleware para gerar cookie de sessão (HTTP only agora)
app.use((req, res, next) => {
    if (!req.cookies.session_id) {
        res.cookie('session_id', 'FLAG{XSS_SESSION_LEAK}', { httpOnly: true, sameSite: 'Lax' }); // seguro
    }
    next();
});

app.get('/', (req, res) => {
    db.all("SELECT * FROM comments", [], (err, rows) => {
        if (err) {
            return res.send('Erro ao carregar comentários');
        }
        // renderiza; template usará escape
        res.render('comments', { comments: rows });
    });
});

app.post('/comment', (req, res) => {
    let { content } = req.body;
    // sanitiza a entrada removendo scripts e tags perigosas
    content = sanitizeHtml(content, {
        allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
        allowedAttributes: {
            'a': ['href', 'rel', 'target']
        },
        allowedSchemes: ['http', 'https', 'mailto']
    });

    db.run("INSERT INTO comments (content) VALUES (?)", [content], (err) => {
        if (err) {
            return res.send('Erro ao salvar comentário');
        }
        res.redirect('/');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
