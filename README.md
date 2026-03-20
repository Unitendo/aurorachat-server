<h1 align="center">Welcome to the aurorachat repository!</h1>
This is the server for Aurorachat.<br>
For clients and stuff, see the <a href="https://github.com/Unitendo/aurorachat">main repo</a>.
The license, code of conduct, and security/contributing guidelines in the main repo also apply here.

<br>This repository is <b>open</b> for contributions! If you'd like to, you may open a PR or an issue, contributing helps us as we develop aurorachat!

<h1 align="center">How to Run the Server</h1>

> [!WARNING]
> Python 3.14+ may cause compatibility issues. Please use Python 3.13 or earlier.

### 1. Clone the repository
```
git clone https://github.com/Unitendo/aurorachat-server.git
cd aurorachat-server
```

### 2. Set up environment variables
Copy the `.env.example` file and rename it to `.env`:
```
cp .env.example .env
```
This file contains environment variables that you can modify to your liking.

### 3. Install dependencies
```
pip install flask flask-socketio flask-cors better-profanity bcrypt python-dotenv
```

### 4. Run the server
```
python server.py
```
