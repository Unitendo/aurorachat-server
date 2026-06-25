# Welcome to the aurorachat repository #

This is the server for Aurorachat.  
For clients and stuff, see the [main repo](https://github.com/Unitendo/aurorachat).  
The license, code of conduct, and security/contributing guidelines in the main repo also apply here.

This repository is **open** for contributions! If you'd like to, you may open a PR or an issue, contributing helps us as we develop aurorachat!

## How to Run the Server ##

### Running AUC v6 ###

```bash
git clone https://github.com/Unitendo/aurorachat-server.git
cd aurorachat-server

# Install dependencies
npm install express express-session bcryptjs jsonwebtoken

# Setup server configuration
cp config.example.js config.js
# Now would be a great time to edit config.js

node server.js
```
