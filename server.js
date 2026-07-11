const config = require('./config') // .env but shittier (tm)
const express = require('express'); // express, used for webserver actions
const net = require('net'); // net, used for socket functions
const session = require('express-session'); // express-session, used for the admin panel
const bcrypt = require('bcryptjs'); // BCrypt, used for hashing passwords
const jwt = require('jsonwebtoken'); // JSON Web Token, used for authentication instead of manually using IPs (stupid behavior)
const path = require('path'); // Wait, what?
const fs = require('fs'); // Filesystem actions
const websocket = require('ws'); // WebSocket server, for the web client
const crypto = require('crypto'); // to generate the encryption key

const { 
  TOKEN_SECRET, SESSION_SECRET,
  HTTP_PORT, SOCKET_PORT, WEBSOCKET_PORT
} = config

const app = express(); // Create the actual server (the express one anyway)
// this is moved
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
  "roleplay",
  "testing channel",
  "Bro_POTTER12's gambling cave",
  "my time channel for cool guy to sing my time",
];

const HISTORY_LIMIT = 100; // Easily changeable if moments pass. Shattered glass? Hands of time. Where's that chime?!
/**
 * @type { Object.<string,{ username: string, message: string }[]> }
 */
const chatHistory = {};

// generating the servers encryption keys
const server = crypto.generateKeyPairSync('x25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// function to decypt
function decypt(enc_msg, clientKey) {
  const [ivHex, authTagHex, encryptedHex] = enc_msg.split(':');
  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(server.privateKey),
    publicKey: crypto.createPublicKey(clientKey)
  });
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', sharedSecret, iv);
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// function to encrypt
function encrypt(text, clientKey) {
  const sharedSecret = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey(server.privateKey),
    publicKey: crypto.createPublicKey(clientKey)
  });
  if (!clientKey) {
    console.log("someone tried to crash the server (or they're just dumb)");
    return text; 
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sharedSecret, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

// where we store the client keys
const clientKeys = {};

// redefining res.send
app.use((req, res, next) => {
  const originalSend = res.send;
  res.send = function (body) {
    let modifiedBody = encrypt(body, clientKeys.req.ip);
    if (typeof body === 'string' || Buffer.isBuffer(body)) {
    }
    return originalSend.apply(this, [modifiedBody]);
  };
  next();
})
app.use(express.text()); // Make sure to accept raw text because JSON parsing in base C is hell

// Initialize an empty history array for every single room
for(const room of rooms) {
  chatHistory[room] = []
}

const RECENT_LIMIT = 10; // How many recent messages to replay to clients on connect
// Ring buffer of the last few broadcast lines (stored verbatim so replay is byte-identical to a live broadcast)
/** @type { string[] } */
const recentMessages = [];

// The amount of rooms the client should parse (calculate dynamically in the future when user-created rooms exist)
const roomCount = rooms.length;

// Client storage, keeps track of all sockets.
const clients = [];

const socket_server = net.createServer((socket) => {
  const {ip, port} = socket.address;
  console.log(`[${socket.remoteAddress}] Client connected`);
  clients.push(socket);

  // Replay recent messages so there's some permanence across reconnects
  for(const line of recentMessages) {
    socket.write(line);
  }

  socket.on('data', (data) => {
    const msg = data.toString('utf-8').trim()
    const parts = msg.split('|')

    if(parts[0] === 'history') {
      let limit = parts[1] ? parseInt(parts[1]) : 0
      const room = parts[2]
      if(limit == NaN) limit = 0
      if(limit < 0) limit = 0
      let message = ''
      if(room) {
        const history = chatHistory[room]
        if(history) 
          for(const msg of history) {
            message += `${msg.username}|${msg.message}|${room}|\n`
          }
        else {
          console.log(`${socket.remoteAddress} requested message history for nonexistent room (${room})`)
          return
        }
      } else for(const room in chatHistory) {
        const history = chatHistory[room]
        for(const msg of history) {
          message += `${msg.username}|${msg.message}|${room}|\n`
        }
      }
      if(limit && message.length > limit) {
        message = message.substring(message.length - limit, message.length)
      }
      if (!clientKeys[socket.remoteAddress]) {
        console.log("someone tried to crash the server (or they're just dumb)");
        socket.write(message);
        return
      }
      const encryptedMsg = encrypt(message, clientKeys[socket.remoteAddress]);
      socket.write(encryptedMsg);
      console.log(`${socket.remoteAddress} requested message history`)
      return
    }

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

  // Replay recent messages so there's some permanence across reconnects
  for(const line of recentMessages) {
    ws.send(line);
  }

  ws.on('message', (data) => {
    const msg = data.toString('utf-8').trim()
    const parts = msg.split('|')

    if(parts[0] === 'history') {
      let limit = parts[1] ? parseInt(parts[1]) : 0
      const room = parts[2]
      if(limit == NaN) limit = 0
      if(limit < 0) limit = 0
      let message = ''
      if(room) {
        const history = chatHistory[room]
        if(history) 
          for(const msg of history) {
            message += `${msg.username}|${msg.message}|${room}|\n`
          }
        else {
          console.log(`${req.socket.remoteAddress} requested message history for nonexistent room (${room})`)
          return
        }
      } else for(const room in chatHistory) {
        const history = chatHistory[room]
        for(const msg of history) {
          message += `${msg.username}|${msg.message}|${room}|\n`
        }
      }
      if(limit && message.length > limit) {
        message = message.substring(message.length - limit, message.length)
      }
      if (!clientKeys[req.socket.remoteAddress]) {
        console.log("someone tried to crash the server (or they're just dumb)");
        ws.send(message);
        return
      }
      const encryptedMsg = encrypt(message, clientKeys[req.socket.remoteAddress]);
      ws.send(encryptedMsg);
      console.log(`${req.socket.remoteAddress} requested message history`)
      return
    }

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
    return res.status(400).send("ERR_INVALID_TOKEN");
  }

  try {
    const decoded = jwt.verify(token, TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.log(`AHHHH OH HELP OH MY GOODNESS AHHHH ${err}`);
    return res.status(500).send("ERR_WHAT_THE_HECK");
  }
}

// Check if an IP is banned
function checkBan(req, res, next) {
  const users = readUsers();
  const user = users.users.find(user => user.ip === req.ip);
  if (user) {
    if (user.banned == true) {
      console.log(`Banned user attempted access: ${user.username}`);
      const reason = user.banReason || "No reason specified";
      return res.status(403).send(`ERR_BANNED|${reason}|`);
    } else {
      next();
    }
  } else {
    next();
  }
}

/*
extanging encrytion keys
content should be the clients public encryption key
*/
app.post('/api/key', checkBan, (req, res) => {
  res.set('Content-Type', 'text/plain');
  const ip = req.ip;
  if (!ip in clientKeys) {
    const key = req.body;
    clientKeys[ip] = key;
    res.status(200)
    res.originalSend.call(res, server.publicKey);
    console.log("Client conected");
  } else {
    res.status(409);
    res.originalSend.call(res, "ALREADY CONNECTED");
  }
});

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
  const ip = req.ip;
  const decBody = decrypt(res.body, clientKeys.ip);
  const splittered = decBody.split("|");
  if (!splittered[1] || !splittered[0]) {
    return res.status(406).send("ERR_MISSING_FIELD");
  }
  if (!rooms.includes(splittered[1])) {
    return res.status(404).send("ERR_FAKE_ROOM_YOU_MORON");
  }
  if (splittered[1] == "announcements") {
    console.log("Message in announcements:");
    const users = readUsers();
    const user = users.users.find(user => user.username === req.user.username);
    if (user) {
      if (user.admin == false) {
        console.log("Not enough rights");
        return res.status(403).send("ERR_NO_RIGHTS");
      }
    }
  }
  const users2 = readUsers();
  const user2 = users2.users.find(user => user.username === req.user.username);
  if (user2) {
    if (user2.banned) {
      const reason = user2.banReason || "No reason specified";
      return res.status(403).send(`ERR_BANNED|${reason}|`);
    }
    if (user2.muted) {
      console.log(`Muted user ${req.user.username} tried to chat.`);
      return res.status(403).send("ERR_MUTED");
    }
  } else {
    return res.status(404).send("ERR_FAKE_USER");
  }
  console.log(`[${req.ip}] ${req.user.username}: ${req.body.split('|')[0]}`);
  console.log(`recieved:`,req.body);
  const currentRoom = splittered[1];
  const msgText = splittered[0];

  if (chatHistory[currentRoom]) {
    chatHistory[currentRoom].push({
      username: req.user.username,
      message: msgText
    });

    // drop the oldest message if we exceed it
    if (chatHistory[currentRoom].length > HISTORY_LIMIT) {
      chatHistory[currentRoom].splice(0, chatHistory[currentRoom].length - HISTORY_LIMIT)
    }
  }

  const line = `${req.user.username}|${req.body}|\n`;

  // Cache the last few messages so we can replay them to clients on connect
  recentMessages.push(line);
  if (recentMessages.length > RECENT_LIMIT) {
    recentMessages.splice(0, recentMessages.length - RECENT_LIMIT);
  }

  clients.forEach(client => {
    client.write(line);
  });
  ws_server.clients.forEach(ws => {
    ws.send(line);
  });
  return res.status(200).send("OK");
});


/*
Account Signup

Formatting:
username|password|


*/
app.post('/api/signup', checkBan, async (req, res) => {
  const ip = req.ip;
  const decBody = decrypt(res.body, clientKeys.ip);
  const splitten = decBody.split("|");
  const username = splitten[0];
  const password = splitten[1];

  if (!username || !password) {
    console.log("Signup: missing fields");
    return res.status(406).send("ERR_MISSING_INPUT");
  }

  const users = readUsers();
  if (users.users.find(user => user.username === username)) {
    console.log("Signup: account already in use");
    return res.status(409).send("ERR_USER_USED");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now().toString(), username, password: hashedPassword, admin: false, ip: req.ip, banned: false, banReason: "", muted: false };
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
  const ip = req.ip;
  const decBody = decrypt(res.body, clientKeys.ip);
  const splitten = decBody.split("|");
  const username = splitten[0];
  const password = splitten[1];

  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    console.log("Wrong password");
    return res.status(401).send("ERR_WRONG_PASS");
  }

  if (user) {
    if (user.banned) {
      const reason = user.banReason || "No reason specified";
      return res.status(403).send(`ERR_BANNED|${reason}|\n`);
    }
  } else {
    return res.status(404).send("ERR_FAKE_USER");
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
app.get('/api/rules', async (req, res) => {
  const filePath = path.join(__dirname, 'rules.txt');
  res.sendFile(filePath, (err) => {
      if (err) {
          console.error(err);
          if (!res.headersSent) {
              res.status(500).send('* If you are reading this,&  I messed up somehow./%');
          }
      }
  });
});
app.get('/api/faq', async (req, res) => {
  const filePath = path.join(__dirname, 'faq.txt');
  res.sendFile(filePath, (err) => {
    if (err) {
      console.error(err);
      if (!res.headersSent) {
        res.status(500).send('* If you are reading this,&  I messed up somehow./%');
      }
    }
  });
});
app.get('/api/changelog', async (req, res) => {
  const filePath = path.join(__dirname, 'changelog.txt');
  res.sendFile(filePath, (err) => {
    if (err) {
      console.error(err);
      if (!res.headersSent) {
        res.status(500).send('* If you are reading this,&  I messed up somehow./%');
      }
    }
  });
});

app.post('/api/online', async (req, res) => {
  room = req.body;
  // get online count for room, currently placeholder
  res.status(501).send("?")
})

app.get('/admin/login', async (req, res) => {
  res.originalSend.call(res, `
    <form method="POST">
        <input name="username" placeholder="Username" required />
        <input name="password" type="password" placeholder="Password" required />
        <button type="submit">Login</button>
    </form>
    `);
});
app.post('/admin/login', async (req, res) => {
  const {username, password} = req.body;
  const users = readUsers();
  const user = users.admins.find(user => user.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    console.log("Wrong password");
    res.status(403)
    return res.originalSend.call(res, `<p><a href="https://www.youtube.com/watch?v=dWX8Kafsc3c">Wrong password.</a></p><a href='/admin/login'>Go back</a>`);
  }

  if (!user) {
    res.status(403)
    return res.originalSend.call(res, `<p><a href="https://www.youtube.com/watch?v=dWX8Kafsc3c">Wrong password.</a></p><a href='/admin/login'>Go back</a>`);
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
  res.originalSend.call(res, `
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
        <a style='color: red;' href='/admin/mute'>Mute User</a><br>
        <a style='color: red;' href='/admin/ban'>Ban User</a><br>
        <a style='color: red;' href='/admin/delete'>Delete User</a><br>
        <h2>User Positive Actions</h2>
        <a style='color: green;' href='/admin/createAccount'>Create Account</a><br>
        <a style='color: #33351c;' href='/admin/unmute'>Unmute User</a><br>
        <a style='color: #e79b0d;' href='/admin/unban'>Unban User</a><br>
        <h2>Miscellaneous</h2>
        <a style='color: blue;' href='/admin/userinfo'>Check User Information</a><br>
        <a style='color: blue;' href='/admin/userswithip'>Check Users with IP</a><br>
        <a style='color: green;' href='/admin/changebanreason'>Change User Ban Reason</a><br>
      </body>
    </html>
  `);
});

app.get('/admin/ban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
        <input name="username" placeholder="Username to ban" required /><br><br>
        <input name="reason" placeholder="Reason for ban" style="width: 300px;" /><br><br>
        <button type="submit">Ban</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/ban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username, reason} = req.body;
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (user) {
    user.banned = true;
    user.banReason = reason || "No reason specified";
  }
  writeUsers(users);

  return res.originalSend.call(res, `
    <p>User banned!</p>
    <p>Reason: ${reason || "No reason specified"}</p>
    <a href="/admin">Go back</a>
    `);
});
app.get('/admin/unban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
      <h1>Unban User</h1>
      <form method="POST">
        <input name="username" placeholder="Username to unban" /><br>
        <button type="submit">Unban</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/unban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username} = req.body;
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (user) {
    user.banned = false;
    user.banReason = "";
  }
  writeUsers(users);

  return res.originalSend.call(res, `
    <p>User unbanned!</p>
    <a href="/admin">Go back</a>
    `);
});

app.get('/admin/delete', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
        <input name="username" placeholder="Username to murder in real life" /><br>
        <button type="submit">Send hitmen</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/delete', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username} = req.body;
  const users = readUsers();
  users.users = users.users.filter(user => user.username !== username);
  writeUsers(users);

  return res.originalSend.call(res, `
    <p>User deleted!</p>
    <a href="/admin">Go back</a>
    `);
});
app.get('/admin/mute', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
      <h1 style='color: red;'>Mute User</h1>
      <form method="POST">
        <input name="username" placeholder="Username to mute" /><br>
        <button type="submit">Mute user</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/mute', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const { username } = req.body;
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  
  // Commit the mute to the database
  if (user) {
    user.muted = true;
    writeUsers(users);
  }

  return res.originalSend.call(res, `
    <p>User Where... Where am I? Hello...? Anyone...? Is... is anybody out there...? Someone!? Anyone!? Can anyone hear me!? ... It's dark. It's so dark here. Someone, anyone, if you can hear me... Say something... please...</p>
    <a href="/admin">Go back</a>
    `);
});
app.get('/admin/unmute', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
      <h1 style='color: green;'>Unmute User</h1>
      <form method="POST">
        <input name="username" placeholder="Username to unmute" /><br>
        <button type="submit">Unmute user</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/unmute', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const { username } = req.body;
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  
  if (user) {
    user.muted = false;
    writeUsers(users);
  }


  return res.originalSend.call(res, `
    <p>User unmuted!</p>
    <a href="/admin">Go back</a>
    `);
});

app.get('/admin/createAccount', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
        <input name="password" placeholder="Password" /><br>
        <input name="passwordHash" placeholder="Password Hash" /><br>
        <button type="submit">Create Account</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/createAccount', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username, password, passwordHash} = req.body;
  

  const users = readUsers();
  if (users.users.find(user => user.username === username)) {
    console.log("Signup: account already in use");
    res.status(409)
    return res.originalSend.call(res, "ERR_USER_USED");
  }

  var hashedPassword;
  if (!passwordHash) {
    hashedPassword = await bcrypt.hash(password, 10);
  } else if (!password) {
    hashedPassword = passwordHash
  } else {
      return res.originalSend.call(res, `
        <p>You need to at least include a password or a password hash.</p>
        <a href="/admin">Go back</a>
        `);
  }
  
  const newUser = { id: Date.now().toString(), username, password: hashedPassword, admin: false, ip: req.ip, banned: false, banReason: "", muted: false };
  users.users.push(newUser);
  writeUsers(users);

  res.originalSend.call(res, `
    <p>User created!</p>
    <a href="/admin">Go back</a>
    `);
});

app.get('/admin/userinfo', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
      <h1 style='color: green;'>Check User Information</h1>
      <form method="POST">
        <input name="username" placeholder="Username" required /><br>
        <button type="submit">Grab Info</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/userinfo', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username} = req.body;
  
  const users = readUsers();
  const user = users.users.find(user => user.username === username);

  return res.originalSend.call(res, `
    <p>Username: ${user.username}<br>Password Hash: ${user.password}<br>ID: ${user.id}<br>Banned: ${user.banned}<br>Ban Reason: ${user.banReason || "None"}<br>Muted: ${user.muted}<br>IP: <a href="#" onclick="return postName(this)">${user.ip}</a></p>
    <a href="/admin">Go back</a>
    <script>
    // are you gonna finish that croissant?
    function postName(el) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/admin/userswithip';

        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'ip';
        input.value = '${user.ip}';

        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();

        return false;
    }
    </script>
    `);
});
app.post('/api/isadmin', async (req, res) => {
  const {username} = req.body;
  
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (!user) {
    return res.status(404).send("Invalid user yo");
  }
  res.status(200).send(`${user.admin}`)
});

app.get('/admin/userswithip', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
      <h1 style='color: green;'>Check Users with IP</h1>
      <form method="POST">
        <input name="ip" placeholder="IP" required /><br>
        <button type="submit">Grab Users</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/userswithip', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {ip} = req.body;
  
  const users = readUsers()["users"];
  const matches = users.filter(item => item.ip === ip).map(item => item.username);
  const usernamesHtml = matches.map(username => `<a href="#" onclick="return postName(this)"><p>${username}</p></a>`).join("\n");

  return res.originalSend.call(res, `
    ${usernamesHtml}
    <a href="/admin">Go back</a>
    <script>
    // NOTE: this is some bullshit i have to use to make the actual "clickable username" thing work. - 3pm
    function postName(el) {
        const username = el.textContent.trim();

        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/admin/userinfo';

        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'username';
        input.value = username;

        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();

        return false;
    }
    </script>
    `);
});

app.get('/admin/changebanreason', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  return res.originalSend.call(res, `
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
      <h1 style='color: green;'>Change User Ban Reason</h1>
      <form method="POST">
        <input name="username" placeholder="Username" required /><br>
        <input name="reason" placeholder="New Ban Reason" required /><br>
        <button type="submit">Change Ban Reason</button>
    </form>
    </body>
    </html>
  `);
});

app.post('/admin/changebanreason', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
  }
  const {username, reason} = req.body;
  const users = readUsers();
  const user = users.users.find(user => user.username === username);
  if (user) {
    user.banReason = reason || "No reason specified";
  }
  writeUsers(users);

  return res.originalSend.call(res, `
    <p>Changed user ban reason!</p>
    <p>Reason: ${reason || "No reason specified"}</p>
    <a href="/admin">Go back</a>
    `);
});

app.listen(HTTP_PORT, () => {
  console.log(`AuroraHTTP running on port ${HTTP_PORT}`);
});
