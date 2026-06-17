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
  "roleplay",
  "testing channel",
];

const HISTORY_LIMIT = 100; // Easily changeable if moments pass. Shattered glass? Hands of time. Where's that chime?!
/**
 * @type { Object.<string,{ username: string, message: string }[]> }
 */
const chatHistory = {};

// Initialize an empty history array for every single room
for(const room of rooms) {
  chatHistory[room] = []
}

// The amount of rooms the client should parse (calculate dynamically in the future when user-created rooms exist)
const roomCount = rooms.length;

// Client storage, keeps track of all sockets.
const clients = [];

const socket_server = net.createServer((socket) => {
  const {ip, port} = socket.address;
  console.log(`[${socket.remoteAddress}] Client connected`);
  clients.push(socket);

  socket.on('data', (data) => {
    const msg = data.toString('utf-8').trim()

    if(msg === 'history') {
      for(const room in chatHistory) {
        const history = chatHistory[room]
        for(const msg of history) {
          socket.write(`${msg.username}|${msg.message}|${room}|\n`)
        }
      }
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

  ws.on('message', (data) => {
    const msg = data.toString('utf-8').trim()

    if(msg === 'history') {
      for(const room in chatHistory) {
        const history = chatHistory[room]
        for(const msg of history) {
          ws.send(`${msg.username}|${msg.message}|${room}|\n`)
        }
      }
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
      console.log(`Banned user attempted access: ${user.username}`);
      const reason = user.banReason || "No reason specified";
      return res.send(`ERR_BANNED|${reason}|`);
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
      const reason = user2.banReason || "No reason specified";
      return res.status(200).send(`ERR_BANNED|${reason}|`);
    }
    if (user2.muted) {
      console.log(`Muted user ${req.user.username} tried to chat.`);
      return res.status(200).send("ERR_MUTED");
    }
  } else {
    return res.status(200).send("ERR_FAKE_USER");
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
      const reason = user.banReason || "No reason specified";
      return res.status(200).send(`ERR_BANNED|${reason}|\n`);
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
app.get('/api/rules', async (req, res) => {
  const filePath = path.join(__dirname, 'rules.txt');
  res.sendFile(filePath, (err) => {
      if (err) {
          console.error(err);
          if (!res.headersSent) {
              res.status(404).send('* If you are reading this,&  I messed up somehow./%');
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
        res.status(404).send('* If you are reading this,&  I messed up somehow./%');
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
        res.status(404).send('* If you are reading this,&  I messed up somehow./%');
      }
    }
  });
});

app.post('/api/online', async (req, res) => {
  room = req.body;
  // get online count for room, currently placeholder
  res.status(200).send("?")
})

app.get('/admin/login', async (req, res) => {
  res.send(`
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
    return res.status(403).send(`<p><a href="https://www.youtube.com/watch?v=dWX8Kafsc3c">Wrong password.</a></p><a href='/admin/login'>Go back</a>`);
  }

  if (!user) {
    return res.status(403).send(`<p><a href="https://www.youtube.com/watch?v=dWX8Kafsc3c">Wrong password.</a></p><a href='/admin/login'>Go back</a>`);
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
        <a style='color: red;' href='/admin/mute'>Mute User</a><br>
        <a style='color: red;' href='/admin/ban'>Ban User</a><br>
        <a style='color: red;' href='/admin/delete'>Delete User</a><br>
        <h2>User Positive Actions</h2>
        <a style='color: green;' href='/admin/createAccount'>Create Account</a><br>
        <a style='color: blue;' href='/admin/userinfo'>Check User Information</a><br>
        <a style='color: #33351c;' href='/admin/unmute'>Unmute User</a><br>
        <a style='color: yellow;' href='/admin/unban'>Unban User</a><br>
      </body>
    </html>
  `);
});

app.get('/admin/ban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
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

  return res.send(`
    <p>User banned!</p>
    <p>Reason: ${reason || "No reason specified"}</p>
    <a href="/admin">Go back</a>
    `);
});
app.get('/admin/unban', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
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

  return res.send(`
    <p>User unbanned!</p>
    <a href="/admin">Go back</a>
    `);
});

app.get('/admin/delete', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
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

  return res.send(`
    <p>User deleted!</p>
    <a href="/admin">Go back</a>
    `);
});
app.get('/admin/mute', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
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

  return res.send(`
    <p>User Where... Where am I? Hello...? Anyone...? Is... is anybody out there...? Someone!? Anyone!? Can anyone hear me!? ... It's dark. It's so dark here. Someone, anyone, if you can hear me... Say something... please...</p>
    <a href="/admin">Go back</a>
    `);
});
app.get('/admin/unmute', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
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


  return res.send(`
    <p>User unmuted!</p>
    <a href="/admin">Go back</a>
    `);
});

app.get('/admin/createAccount', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
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
    </body>
    </html>
  `);
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
  const newUser = { id: Date.now().toString(), username, password: hashedPassword, admin: false, ip: req.ip, banned: false, banReason: "", muted: false };
  users.users.push(newUser);
  writeUsers(users);

  return res.send(`
    <p>User created!</p>
    <a href="/admin">Go back</a>
    `);
});

app.get('/admin/userinfo', async (req, res) => {
  if (!req.session.admin) {
    return res.redirect("/admin/login");
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

  return res.send(`
    <p>Username: ${user.username}<br>Password Hash: ${user.password}<br>ID: ${user.id}<br>Banned: ${user.banned}<br>Ban Reason: ${user.banReason || "None"}<br>Muted: ${user.muted}</p>
    <a href="/admin">Go back</a>
    `);
});

app.listen(HTTP_PORT, () => {
  console.log(`AuroraHTTP running on port ${HTTP_PORT}`);
});
