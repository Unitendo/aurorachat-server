const express = require('express');
const net = require('net');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');


const app = express();
app.use(express.text());
const USERS_FILE = path.join(__dirname, 'users.json');
const SECRET_KEY = 'ENTER YOUR KEY HERE';

function readUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      return { users: [], admins: [] };
    }

    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error("Failed to read users.json:", err);
    return { users: [], admins: [] };
  }
}

function writeUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

const rooms = [
  "general",
  "announcements",
  "bots",
  "lounge",
  "luigi chat",
];

const roomCount = rooms.length;

const clients = [];

const server = net.createServer((socket) => {
  const {ip, port} = socket.address;
  console.log(`[${socket.remoteAddress}] Client connected`);
  clients.push(socket);

  socket.on('data', (data) => {
    console.log(`${socket.remoteAddress} tried sending data (Murder him)`);
  });

  socket.on('end', () => {
    console.log(`[${socket.remoteAddress}] Client disconnected`);
  });

  socket.on('error', (err) => {
    console.error(`[${socket.remoteAddress}] error: ${err.message}`);
  });
});

server.listen(3033, () => {
  console.log(`AuroraTCP listening on port 3033`);
});

function verifyToken(req, res, next) {
  const token = req.headers['auth'];

  if (!token) {
    return res.send("ERR_INVALID_TOKEN");
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    console.log(`AHHHH OH HELP OH MY GOODNESS AHHHH ${err}`);
    return res.send("ERR_WHAT_THE_HECK");
  }
}

function checkBan(req, res, next) {
  const users = readUsers();
  const user = users.users.find(user => user.ip === req.ip);
  if (user) {
    if (user.banned == true) {
      return res.send("ERR_BANNED");
    } else {
      next();
    }
  } else {
    next();
  }
}

app.post('/api/test', checkBan, (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.status(200).send('Online');
  console.log("Client requested API status");
});

app.post('/api/rooms', checkBan, (req, res) => {
  res.set('Content-Type', 'text/plain');
  const responseString = `${roomCount}|${rooms.join('|')}|`;
  res.status(200).send(responseString);
  console.log("Sent room list");
});

app.post('/api/chat', verifyToken, checkBan, (req, res) => {
  const splittered = req.body.split("|");
  if (splittered[1] == "announcements") {
    console.log("Message in announcements:");
    const users = readUsers();
    const user = users.users.find(user => user.username === req.user.username);
    if (user) {
      if (user.admin == false) {
        console.log("Not enough rights");
        return res.status(200).send("ERR_NO_RIGHTS");
      }
    }
  }
  console.log(`[${req.ip}] ${req.user.username}: ${req.body.split('|')[0]}`);
  clients.forEach(client => {
    client.write(`${req.user.username}|${req.body}|\n`);
  });
  return res.status(200).send("OK");
});

app.post('/api/signup', checkBan, async (req, res) => {
  const splitten = req.body.split("|");
  const username = splitten[0];
  const password = splitten[1];

  if (!username || !password) {
    console.log("Signup: missing fields");
    return res.status(200).send("ERR_MISSING_INPUT");
  }

  const users = readUsers();
  if (users.users.find(user => user.username === username)) {
    console.log("Signup: account already in use");
    return res.status(200).send("ERR_USER_USED");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), username, password: hashedPassword, admin: false, ip: req.ip, banned: false };
  users.users.push(newUser);
  writeUsers(users);

  const token = jwt.sign({ id: newUser.id, username }, SECRET_KEY, { expiresIn: '1h' });
  console.log("Account created!")
  return res.status(200).send(`${token}`);
});

app.post('/api/login', checkBan, async (req, res) => {
  const splitten = req.body.split("|");
  const username = splitten[0];
  const password = splitten[1];

  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    console.log("Wrong password");
    return res.status(200).send("ERR_WRONG_PASS");
  }

  const token = jwt.sign({ id: user.id, username }, SECRET_KEY, { expiresIn: '1h' });
  console.log("Client logged in!");
  return res.status(200).send(`${token}|\n`);
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'ENTER A DIFFERENT KEY HERE',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.get('/hidden-secret/admin/login', async (req, res) => {
  res.send(`
    <form method="POST">
        <input name="username" placeholder="Username" required />
        <input name="password" type="password" placeholder="Password" required />
        <button type="submit">Login</button>
    </form>
    `);
});
app.post('/hidden-secret/admin/login', async (req, res) => {
  const {username, password} = req.body;
  const users = readUsers();
  const user = users.admins.find(user => user.username === username);
  if (user)
  if (!user || !(await bcrypt.compare(password, user.password))) {
    console.log("Wrong password");
    return res.status(403).send(`<p>Wrong password.</p><a href='/hidden-secret/admin/login'>Go back</a>`);
  }
  req.session.admin = true;
  if (user.staff === true) {
    req.session.staff = true;
  }

  return res.redirect("/hidden-secret/admin");
});

app.get('/hidden-secret/admin', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/hidden-secret/admin/login");
  }
  res.send(`
    <html>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100..900;1,100..900&display=swap" onload="this.onload=null;this.rel='stylesheet'">
        <noscript>
          <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100..900;1,100..900&display=swap">
        </noscript>

        <style>
          h1, p, h2, a {
            font-family: 'Roboto', Arial, sans-serif;
          }
        </style>
      </head>
      <body>
        <h2>User Negative Actions</h2>
        <a style='color: red;' href='/hidden-secret/admin/ban'>Ban User</a><br>
        <a style='color: red;' href='/hidden-secret/admin/delete'>Delete User</a><br>
        <h2>User Positive Actions</h2>
        <a style='color: green;' href='/hidden-secret/admin/createAccount'>Create Account</a><br>
        <a style='color: blue;' href='/hidden-secret/admin/userinfo'>Check User Information</a><br>
      </body>
    </html>
  `);
});

app.get('/hidden-secret/admin/ban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/hidden-secret/admin/login");
  }
  return res.send(`
    <html>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100..900;1,100..900&display=swap" onload="this.onload=null;this.rel='stylesheet'">

        <style>
          h1, p, h2, a {
            font-family: 'Roboto', Arial, sans-serif;
          }
        </style>
      </head>
      <body>
      <h1>Ban User</h1>
      <form method="POST">
        <input name="username" placeholder="Username to ban" /><br>
        <button type="submit">Ban</button>
    </form>
    </body
    </html>
  `);
});

app.post('/hidden-secret/admin/ban', async (req, res) => {
  if (!req.session.admin) {
    res.redirect("/hidden-secret/admin/login");
  }
  const {username} = req.body;
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (user) {
    user.banned = true;
  }
  writeUsers(users);

  return res.send(`
    <p>User banned!</p>
    <a href="/hidden-secret/admin">Go back</a>
    `);
});

app.get('/hidden-secret/admin/delete', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/hidden-secret/admin/login");
  }
  return res.send(`
    <html>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100..900;1,100..900&display=swap" onload="this.onload=null;this.rel='stylesheet'">

        <style>
          h1, p, h2, a {
            font-family: 'Roboto', Arial, sans-serif;
          }
        </style>
      </head>
      <body>
      <h1 style='color: red;'>Delete User</h1>
      <form method="POST">
        <input name="username" placeholder="Username to ban" /><br>
        <button type="submit">Ban</button>
    </form>
    </body
    </html>
  `);
});

app.post('/hidden-secret/admin/delete', async (req, res) => {
  if (!req.session.admin) {
    res.redirect("/hidden-secret/admin/login");
  }
  const {username} = req.body;
  const users = readUsers();
  users.users = users.users.filter(user => user.username !== username);
  writeUsers(users);

  return res.send(`
    <p>User deleted!</p>
    <a href="/hidden-secret/admin">Go back</a>
    `);
});

app.get('/hidden-secret/admin/createAccount', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/hidden-secret/admin/login");
  }
  return res.send(`
    <html>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100..900;1,100..900&display=swap" onload="this.onload=null;this.rel='stylesheet'">

        <style>
          h1, p, h2, a {
            font-family: 'Roboto', Arial, sans-serif;
          }
        </style>
      </head>
      <body>
      <h1 style='color: green;'>Create User</h1>
      <form method="POST">
        <input name="username" placeholder="Username" required /><br>
        <input name="password" placeholder="Password" required /><br>
        <button type="submit">Create Account</button>
    </form>
    </body
    </html>
  `);
});

app.post('/hidden-secret/admin/createAccount', async (req, res) => {
  if (!req.session.admin) {
    res.redirect("/hidden-secret/admin/login");
  }
  const {username, password} = req.body;
  
  const users = readUsers();
  if (users.users.find(user => user.username === username)) {
    console.log("Signup: account already in use");
    return res.status(409).send("ERR_USER_USED");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), username, password: hashedPassword, admin: false, ip: req.ip, banned: false };
  users.users.push(newUser);
  writeUsers(users);

  return res.send(`
    <p>User deleted!</p>
    <a href="/hidden-secret/admin">Go back</a>
    `);
});

app.get('/hidden-secret/admin/userinfo', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/hidden-secret/admin/login");
  }
  return res.send(`
    <html>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link rel="preload" as="style" href="https://fonts.googleapis.com/css2?family=Roboto:ital,wght@0,100..900;1,100..900&display=swap" onload="this.onload=null;this.rel='stylesheet'">

        <style>
          h1, p, h2, a {
            font-family: 'Roboto', Arial, sans-serif;
          }
        </style>
      </head>
      <body>
      <h1 style='color: green;'>Create User</h1>
      <form method="POST">
        <input name="username" placeholder="Username" required /><br>
        <button type="submit">Create Account</button>
    </form>
    </body
    </html>
  `);
});

app.post('/hidden-secret/admin/userinfo', async (req, res) => {
  if (!req.session.admin) {
    res.redirect("/hidden-secret/admin/login");
  }
  const {username} = req.body;
  
  const users = readUsers();
  const user = users.users.find(user => user.username === username);

  return res.send(`
    <p>Username: ${user.username}<br>Password Hash: ${user.password}<br>ID: ${user.id}<br>Banned: ${user.banned}</p>
    <a href="/hidden-secret/admin">Go back</a>
    `);
});


app.listen(6767, () => {
  console.log('AuroraHTTP running on port 6767');
});