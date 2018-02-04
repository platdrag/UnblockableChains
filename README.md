# About
Nothing interesting yet...

# Dependencies - Python
- python3-bitcoin
- python3-pbkdf2
- py-solc
- web3

# Use - linux
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
