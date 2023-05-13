const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const fs = require("fs");

const app = express();
app.use(bodyParser.json());

let products = [];
let carts = {};

const usersFilePath = "usuarios.json";

// Função para ler usuários do arquivo
function getUsers() {
  try {
    const usersData = fs.readFileSync(usersFilePath);
    const users = JSON.parse(usersData);
    return users;
  } catch (error) {
    if (error.code === "ENOENT") {
      // Arquivo não existe, retornar um array vazio
      return [];
    } else {
      // Outro erro ocorreu, lançar o erro novamente
      throw error;
    }
  }
}

// Função para escrever usuários no arquivo
function saveUsers(users) {
  const data = JSON.stringify(users);
  fs.writeFileSync(usersFilePath, data);
}

// Rota de cadastro de usuário
app.post("/signup", (req, res) => {
  const { username, password, name, confirmPassword } = req.body;

  // Verifica se usuário já existe
  const users = getUsers();
  const user = users.find((u) => u.username === username);
  if (user) {
    return res.status(409).send({ message: "Usuário já existe" });
  }

  // Verifica se a senha e a confirmação de senha são iguais
  if (password !== confirmPassword) {
    return res
      .status(400)
      .send({ message: "A senha e a confirmação de senha não coincidem" });
  }

  // Gera hash da senha
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return res.status(500).send({ message: "Erro ao gerar hash da senha" });
    }

    // Cria novo usuário com senha em hash
    const newUser = { username, name, password: hash };

    // Adiciona novo usuário ao array de usuários e salva no arquivo
    users.push(newUser);
    saveUsers(users);

    return res.status(201).send({ message: "Usuário criado com sucesso" });
  });
});

// Rota de login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Busca usuário pelo nome de usuário
  const users = getUsers();
  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).send({ message: "Usuário ou senha inválidos" });
  }

  // Compara senha em hash com a senha informada
  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) {
      return res.status(401).send({ message: "Usuário ou senha inválidos" });
    }

    // Gera token JWT e retorna para o cliente
    const token = jwt.sign({ username }, "jwtSecretKey", { expiresIn: "1h" });
    return res.status(200).send({ token });
  });
});

// Middleware para autenticação JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res
      .status(401)
      .json({ message: "Token de autenticação não fornecido" });
  }

  jwt.verify(token, "jwtSecretKey", (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ message: "Token de autenticação inválido" });
    }

    req.user = user;
    next();
  });
};

// Rota de cadastro de produto (requer autenticação)
app.post("/products", (req, res) => {
  const { name, description, price } = req.body;
  const id = products.length + 1;

  const newProduct = {
    id,
    name,
    description,
    price,
  };

  products.push(newProduct);
  res.json(newProduct);
});

// Rota para adicionar um produto ao carrinho (requer autenticação)
app.post("/cart/:userId", authenticateJWT, (req, res) => {
  const { userId } = req.params;
  const { productId, quantity } = req.body;

  if (!carts[userId]) {
    carts[userId] = {};
  }

  if (!carts[userId][productId]) {
    carts[userId][productId] = 0;
  }

  carts[userId][productId] += quantity;

  res.json({ message: "Product added to cart" });
});

// Rota para obter o carrinho de um usuário (requer autenticação)
app.get("/cart/:userId", authenticateJWT, (req, res) => {
  const { userId } = req.params;
  const cart = carts[userId] || {};

  res.json(cart);
});

// Rota para finalizar o carrinho de um usuário (requer autenticação)
app.post("/cart/:userId/checkout", (req, res) => {
  const { userId } = req.params;

  carts[userId] = {};

  res.json({ message: "Cart checked out" });
});

// Iniciar o servidor
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
