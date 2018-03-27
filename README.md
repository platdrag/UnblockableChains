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
This project was created for Educational and Research purposes only. It only purpose is to educate the security community of new and possibliy emerging vector that attackers might be using in the future, and should not (and *cannot*) be used in any illegal manner.

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

#
#
# Installation
This project is purposed to run on linux and Windows 10 (with linux subsystem installed) only.

### Dependencies
- python3-bitcoin
- python3-pbkdf2
- py-solc
- web3

### Dependencies - web UI
- python3-flask
- python3-werkzeug
- Flask-Sockets
- gevent-websocket

### Use - linux
- under `conf/deployment/DeploymentConf.BASE.yaml`, adjust the following values:
    - path: solc binary (included under bin/)
    - path: geth binary (included under bin/)
    - path: `BlockChainData`
    - path: `contractUri`
    - path: `genesisFile`
    - path: `keyGenScript

- run the server bootstrap script:

    export PYTHONPATH=src && \
    python3 src/Server/DeployUnstoppableCnC.py .

- run the server in interactive mode & use the `sc` object:

    python3 -i src/Server/ServerCommands.py .
    // ... log output

- generate a new bot client instance:

    >>> sc.generateNewClientInstance(1000000000000000000,opj('conf','clientGen', 'ClientConf.TEMPLATE.yaml'), port=30304)

- generate a new bot client instance:

    export PYTHONPATH=src && \
    python3 -i ./src/Client/ClientCommands.py . generated/0xa55be06.../conf/clientConf.yaml

- back on the server side interactive shell add work to the client:

    >>> sc.addWork('0xa55be06a805566d480103cea559c4d1bc3f729d2', 'echo awesome')
    // ... log output
    ... confirmed match between instance issued command and result: ['echo awesome', 'awsome']


### Use - web UI
- run the deployment script as described above
- create `static/`, `templates` dir symlinks:

    ln -s src-webapp/static .
    ln -s src-webapp/templates .

- run the webapp:

    export PYTHONPATH=src
    python3 src-webapp/ecnc-webapp.py

- access `http://127.0.0.1:5000/`
- generate one or more client kits
- run client nodes accordingly
- wait for the clients to register
- add/rm clients from index
- run shell commands on index-included clients 


# Todos
- Implement public key encryption
- Split fund to generated implant to a small fee up front that will suffice only registration and then transfer the rest after registration.
- Support multiple contract addresses
- Support placing command/result data to Swarm, only put hash on blockchain. 
- Allow Transfer messages using whisper
- Allow controller the return funds from a compromised implant account.
