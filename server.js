const express = require('express'); // express, used for webserver actions
const net = require('net'); // net, used for socket functions
const session = require('express-session'); // express-session, used for the admin panel
const bcrypt = require('bcryptjs'); // BCrypt, used for hashing passwords
const jwt = require('jsonwebtoken'); // JSON Web Token, used for authentication instead of manually using IPs (stupid behavior)
const path = require('path'); // Wait, what?
const fs = require('fs'); // Filesystem actions
const websocket = require('ws'); // WebSocket server, for the web client

const TOKEN_SECRET = "replace with a randomly generated string"; // JWT secret key
const SESSION_SECRET = "replace with a (different) randomly generated string"; // Secret key for admin panel cookies
const HTTP_PORT = 6767;
const SOCKET_PORT = 3033;
const WEBSOCKET_PORT = 3034;

const app = express(); // Create the actual server (the express one anyway)
app.use(express.text()); // Make sure to accept raw text because JSON parsing in base C is hell
const USERS_FILE = path.join(__dirname, 'users.json');

// Read the users file
function readUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      return { users: [], admins: [] };
    }
    const data = fs.readFileSync(USERS_FILE);
    return JSON.parse(data);
  } catch (err) {
    console.error("Failed to read users.json:", err);
    return { users: [], admins: [] };
  }
}

// Write to the users file
function writeUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

// Array that manages the rooms
const rooms = [
  "general",
  "announcements",
  "bots",
  "lounge",
  "luigi chat",
];

// The amount of rooms the client should parse (calculate dynamically in the future when user-created rooms exist)
const roomCount = rooms.length;

// Client storage, keeps track of all sockets.
const clients = [];

const socket_server = net.createServer((socket) => {
  const {ip, port} = socket.address;
  console.log(`[${socket.remoteAddress}] Client connected`);
  clients.push(socket);

  socket.on('data', (data) => {
    console.log(`${socket.remoteAddress} tried sending data (Murder him): ${data}`);
  });

  socket.on('end', () => {
    console.log(`[${socket.remoteAddress}] Client disconnected`);
  });

  socket.on('error', (err) => {
    console.error(`[${socket.remoteAddress}] error: ${err.message}`);
  });
});

// Start up the TCP server
socket_server.listen(SOCKET_PORT, () => {
  console.log(`AuroraTCP listening on port ${SOCKET_PORT}`);
});

// Websocket server
const ws_server = new websocket.Server({ port: WEBSOCKET_PORT, clientTracking: true }, () => {
  console.log(`AuroraWSS listening on port ${WEBSOCKET_PORT}`);
});
// WSS connection handling
ws_server.on('connection', (ws, req) => {
  console.log(`[${req.socket.remoteAddress}] Client connected`);

  ws.on('message', (data) => {
    console.log(`${req.socket.remoteAddress} tried sending data (Murder him): ${data}`);
  });

  ws.on('close', (code, reason) => {
    console.log(`[${req.socket.remoteAddress}] Client disconnected`);
  });

  ws.on('error', (err) => {
    console.log(`[${req.socket.remoteAddress}] error: ${err.message}`);
  });
});

// Verify the JWT token provided by the client
function verifyToken(req, res, next) {
  const token = req.headers['auth'];

  if (!token) {
    console.log(`[${req.ip}]: Error: Invalid Token.`);
    return res.send("ERR_INVALID_TOKEN");
  }

  try {
    const decoded = jwt.verify(token, TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.log(`AHHHH OH HELP OH MY GOODNESS AHHHH ${err}`);
    return res.send("ERR_WHAT_THE_HECK");
  }
}

// Check if an IP is banned
function checkBan(req, res, next) {
  const users = readUsers();
  const user = users.users.find(user => user.ip === req.ip);
  if (user) {
    if (user.banned == true) {
      console.log("Banned user");
      return res.send("ERR_BANNED");
    } else {
      next();
    }
  } else {
    next();
  }
}

// web version
app.use('/web', express.static('web'));

// Unused, simple API test
app.post('/api/test', checkBan, (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.status(200).send('Online');
  console.log("Client requested API status");
});

// Grab rooms
app.post('/api/rooms', checkBan, (req, res) => {
  res.set('Content-Type', 'text/plain');
  const responseString = `${roomCount}|${rooms.join('|')}|`;
  res.status(200).send(responseString);
  console.log("Sent room list");
});

/*
Send a message

Formatting:
message|room|

Make CERTAIN it ends with a |, otherwise it'll get messy sometimes.
*/
app.post('/api/chat', verifyToken, checkBan, async (req, res) => {
  const splittered = req.body.split("|");
  if (!splittered[1] || !splittered[0]) {
    return res.status(200).send("ERR_MISSING_FIELD");
  }
  if (!rooms.includes(splittered[1])) {
    return res.status(200).send("ERR_FAKE_ROOM_YOU_MORON");
  }
  if (splittered[1] == "announcements") {
    console.log("Message in announcements:");
    const users = readUsers();
    const user = users.users.find(user => user.username === req.user.username);
    if (user) {
      if (user.admin == false) {
        console.log("Not enough rights");
        return res.send("ERR_NO_RIGHTS");
      }
    }
  }
  const users2 = readUsers();
  const user2 = users2.users.find(user => user.username === req.user.username);
  if (user2) {
    if (user2.banned) {
      return res.status(200).send("ERR_BANNED");
    }
  } else {
    return res.status(200).send("ERR_FAKE_USER");
  }
  console.log(`[${req.ip}] ${req.user.username}: ${req.body.split('|')[0]}`);
  clients.forEach(client => {
    client.write(`${req.user.username}|${req.body}|\n`);
  });
  ws_server.clients.forEach(ws => {
    ws.send(`${req.user.username}|${req.body}|\n`);
  });
  return res.status(200).send("OK");
});

/*
Account Signup

Formatting:
username|password|


*/
app.post('/api/signup', checkBan, async (req, res) => {
  const splitten = req.body.split("|");
  const username = splitten[0];
  const password = splitten[1];

  if (!username || !password) {
    console.log("Signup: missing fields");
    return res.send("ERR_MISSING_INPUT");
  }

  const users = readUsers();
  if (users.users.find(user => user.username === username)) {
    console.log("Signup: account already in use");
    return res.send("ERR_USER_USED");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), username, password: hashedPassword, admin: false, ip: req.ip, banned: false };
  users.users.push(newUser);
  writeUsers(users);

  const token = jwt.sign({ id: newUser.id, username }, TOKEN_SECRET, { expiresIn: '1h' });
  console.log("Account created!");
  return res.status(200).send(`${token}`);
});

/*
Account Login

Formatting:
username|password|

*/
app.post('/api/login', checkBan, async (req, res) => {
  const splitten = req.body.split("|");
  const username = splitten[0];
  const password = splitten[1];

  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    console.log("Wrong password");
    return res.send("ERR_WRONG_PASS");
  }

  if (user) {
    if (user.banned) {
      return res.status(200).send("ERR_BANNED");
    }
  } else {
    return res.status(200).send("ERR_FAKE_USER");
  }

  const token = jwt.sign({ id: user.id, username }, TOKEN_SECRET, { expiresIn: '1h' });
  console.log("Client logged in!");
  return res.status(200).send(`${token}|\n`);
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

app.get('/admin/login', async (req, res) => {
  fs.readFile('admin-web/login.html', 'utf8', (_, data) => {
    res.send(data);
  });
});

app.post('/admin/login', async (req, res) => {
  const {username, password} = req.body;
  const users = readUsers();
  const user = users.admins.find(user => user.username === username);
  if (!await bcrypt.compare(password, user.password)) {
    console.log("Wrong password");
    fs.readFile('admin-web/login.html', 'utf8', (_, data) => {
      return res.status(403).send(data);
    });
    return // Adding this just in case.
  }

  if (!user) {
    fs.readFile('admin-web/login.html', 'utf8', (_, data) => {
      return res.status(403).send(data);
    });
    return // Same thing here.
  }

  req.session.admin = true;
  if (user.staff === true) {
    req.session.staff = true;
  }

  return res.redirect("/admin");
});

app.get('/admin', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  
  fs.readFile('admin-web/index.html', 'utf8', (_, data) => {
    res.send(data);
  });
});

app.get('/admin/ban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  fs.readFile('admin-web/ban/ban.html', 'utf8', (_, data) => {
    res.send(data);
  });
});

app.post('/admin/ban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username} = req.body;
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (user) {
    user.banned = true; // can't we just delete the account and add the username to a banned list instead?
  }
  writeUsers(users);

  
  fs.readFile('admin-web/ban/banned.html', 'utf8', (_, data) => {
    return res.send(data);
  });
});

app.get('/admin/delete', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  fs.readFile('admin-web/delete/delete.html', 'utf8', (_, data) => {
    return res.send(data);
  });
});

app.post('/admin/delete', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username} = req.body;
  const users = readUsers();
  users.users = users.users.filter(user => user.username !== username);
  writeUsers(users);

  fs.readFile('admin-web/delete/deleted.html', 'utf8', (_, data) => {
    return res.send(data);
  });
});

app.get('/admin/createAccount', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  fs.readFile('admin-web/create/create.html', 'utf8', (_, data) => {
    return res.send(data);
  });
});

app.post('/admin/createAccount', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
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

  fs.readFile('admin-web/create/created.html', 'utf8', (_, data) => {
    return res.send(data);
  });
});

app.get('/admin/userinfo', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  fs.readFile('admin-web/userinfo/userinfoform.html', 'utf8', (_, data) => {
    return res.send(data);
  });
});

app.post('/admin/userinfo', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username} = req.body;
  
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  // <p>Username: ${user.username}<br>Password Hash: ${user.password}<br>ID: ${user.id}<br>Banned: ${user.banned}</p>
  fs.readFile('admin-web/userinfo/userinfo.html', 'utf8', (_, data) => {
    return res.send(
      data.replace("[username]", user.username)
          .replace("[password]", user.password)
          .replace("[id]", user.id)
          .replace("[banned]", user.banned)
    );
  });
});

app.listen(HTTP_PORT, () => {
  console.log(`AuroraHTTP running on port ${HTTP_PORT}`);
});
