class Client {
  constructor(useragent, url, httpport, socketport) {
    this.ua = useragent || "AuC-WebLib";
    this.url = url ? "http://"+url+':'+httpport : ''; // if url is empty, use current server ip/port (as in, the server that this web client is on)
    this.ws = new WebSocket('ws://'+url+':'+socketport);
    this.ws.onopen = function() {
      console.log('Connected via WebSocket');
    }
    this.ws.onmessage = (event) => {
      var data = event.data.split("|").slice(0, -1);
      var result = {}
      result["username"] = data[0];
      result["message"] = data.slice(1,-1).join("|"); // allow for messages with pipes in them
      result["room"] = data.slice(-1,).join("|");
      result["pfp"] = "img/pfp.png"; // placeholder
      result["platform"] = "img/plt/web.png"; // placeholder

      if (this.onMessage) { // check if callback has been created yet
        this.onMessage(result);
      };
    }
    this.ws.onerror = (err) => {
      if (this.onError) {
        this.onError(err);
      };
    }
    this.ws.onclose = () => {
      if (this.onClose) {
        this.onClose();
      };
    }
  }
  async signup(username, password) {
    const response = await fetch(this.url+"/api/signup", {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'User-Agent': this.ua
      },
      body: [username,password].join("|")
    })
    const data = await response.text();
    return data;
  }
  async login(username, password) {
    const response = await fetch(this.url+"/api/login", {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'User-Agent': this.ua
        },
        body: [username,password].join("|")
    })
    const data = await response.text();
    console.log(data)
    return data
  }
  async send(token, msg, room, platform, img) {
    if (!platform) {platform="Web"}
    const response = await fetch(this.url+"/api/chat", {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'User-Agent': this.ua,
          'auth': token
        },
        body: [msg,room].join('|')
    })
    const data = await response.text();
    return data;
  }
  async test() {
    const response = await fetch(this.url+"/api/test", {
        method: 'GET'
    })
    const data = await response.text();
    return data;
  }
  async rooms(token) {
    const response = await fetch(this.url+"/api/rooms", {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'User-Agent': this.ua,
          'auth': token
        }
    })
    const data = await response.text();
    const asList = data.split("|");
    const roomCount = parseInt(asList[0])
    const rooms = asList.slice(1, -1)
    return {
        "count": roomCount,
        "rooms": rooms
    };
    console.log(data)
  }
}
