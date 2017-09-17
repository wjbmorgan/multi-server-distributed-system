package activitystreamer.server;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;



public class ControlSolution extends Control {
	private static final Logger log = LogManager.getLogger();
	private HashSet<Connection> conToSer;
	private HashSet<Connection> conToClient;
	private HashMap<String,String> clientRecord;
	private HashMap<String,Connection> registerLog;
	private HashSet<String> serverIdSet;
	private HashMap<Connection,HashSet<String>> lockAllowReply;
	private String serverId;
	private HashMap<String,String> freeServer;
	private HashMap<Connection,String> loginLog;
	
	JSONParser parser = new JSONParser();
	
	// since control and its subclasses are singleton, we get the singleton this way
	public static ControlSolution getInstance() {
		if(control==null){
			control=new ControlSolution();
		} 
		return (ControlSolution) control;
	}
	
	public ControlSolution() {
		
		super();
		
		conToSer = new HashSet<Connection>();
		conToClient = new HashSet<Connection>();
		clientRecord = new HashMap<String,String>();
		registerLog = new HashMap<String,Connection>();
		serverIdSet = new HashSet<String>();
		lockAllowReply = new HashMap<Connection,HashSet<String>>();
		freeServer = new HashMap<String,String>();
		loginLog = new HashMap<Connection,String>();
		//default username and password
		clientRecord.put("anonymous","");
		
		serverId = Settings.nextSecret();
		
		//show secret
		log.info("sercet is "+serverId);
		
		// check if we should initiate a connection and do so if necessary
		initiateConnection();
		// start the server's activity loop
		// it will call doActivity every few seconds
		start();
	}
	
	/*
	 * a new incoming connection
	 */
	@Override
	public Connection incomingConnection(Socket s) throws IOException{
		
		Connection con = super.incomingConnection(s);
	    
		String data = con.getInreader().readLine();
		
		if(process(con, data)){
			super.connectionClosed(con);
		}
	
		return con;
	}
	
	/*
	 * a new outgoing connection
	 */
	@Override
	public Connection outgoingConnection(Socket s) throws IOException{
		Connection con = super.outgoingConnection(s);
		/*
		 * do additional things here
		 */
		JSONObject response = new JSONObject();
		response.put("command","AUTHENTICATE");
		response.put("secret",Settings.getSecret());
		con.writeMsg(response.toString());
		conToSer.add(con);
		return con;
	}
	
	
	/*
	 * the connection has been closed
	 */
	@Override
	public void connectionClosed(Connection con){
		
		if(conToClient.contains(con)){
			conToClient.remove(con);
			loginLog.remove(con);
		}
		else{
			conToSer.remove(con);
		}
		super.connectionClosed(con);
	}
	
	
	/*
	 * process incoming msg, from connection con
	 * return true if the connection should be closed, false otherwise
	 */
	@Override
	public synchronized boolean process(Connection con,String msg){
		
		log.debug(msg);
		try{
			
			JSONObject obj = (JSONObject) parser.parse(msg);
			
			if(!obj.containsKey("command")){
				
				return invalidMessage(con,"no command");
				
			}

			Object command = obj.get("command");	
			switch (command.toString()) {
			
				case "INVALID_MESSAGE":
					
					return true;
					
				case "SERVER_ANNOUNCE":
					
					if(!obj.containsKey("id")) return invalidMessage(con,"no id");
					if(!obj.containsKey("load")) return invalidMessage(con,"no load");
					if(!obj.containsKey("hostname")) return invalidMessage(con,"no hostname");
					if(!obj.containsKey("port")) return invalidMessage(con,"no port");
					return serverAnnounce(con,obj);
					
				case "AUTHENTICATE":
					
					if(!obj.containsKey("secret")) return invalidMessage(con,"no secret");
					return authenticate(con,obj);
					
				case "LOGOUT":
					
					return logOut(con,obj);
					
				case "ACTIVITY_BROADCAST":
					
					if(!obj.containsKey("activity")) return invalidMessage(con,"no activity");
					return activityBroadcast(con,obj);

				case "LOGIN" :
					
					if(!obj.containsKey("username")) return invalidMessage(con,"no username");
					if(!obj.containsKey("secret")) return invalidMessage(con,"no secret");
					log.info(conToClient.size());
					return login(con,obj);
					
				case "ACTIVITY_MESSAGE":
					
					if(!obj.containsKey("username")) return invalidMessage(con,"no username");
					if(!obj.containsKey("secret")) return invalidMessage(con,"no secret");
					if(!obj.containsKey("activity")) return invalidMessage(con,"no activity");
					return activityMessage(con,obj);
					
				case "REGISTER":
					
					if(!obj.containsKey("username")) return invalidMessage(con,"no username");
					if(!obj.containsKey("secret")) return invalidMessage(con,"no secret");
					return register(con,obj);
					
				case "LOCK_REQUEST":
					
					if(!obj.containsKey("username")) return invalidMessage(con,"no username");
					if(!obj.containsKey("secret")) return invalidMessage(con,"no secret");
					return lockRequest(con,obj);
					
				case "LOCK_DENIED":
					
					if(!obj.containsKey("username")) return invalidMessage(con,"no username");
					if(!obj.containsKey("secret")) return invalidMessage(con,"no secret");
					return lockDenied(con,obj);
					
				case "LOCK_ALLOWED":
					
					if(!obj.containsKey("username")) return invalidMessage(con,"no username");
					if(!obj.containsKey("secret")) return invalidMessage(con,"no secret");
					return lockAllowed(con,obj);
					
				case "AUTHENTICATION_FAIL":
					
					if(!obj.containsKey("info")) return invalidMessage(con,"no info");
					return true;
					
				default:
					
					return invalidMessage(con,"invalidMessage");
					
				}
				
		}
		catch (ParseException e) {
			e.printStackTrace();
		}
		return false;
	}

	
	
	/*
	 * Called once every few seconds
	 * Return true if server should shut down, false otherwise
	 */
	@Override
	public boolean doActivity(){
		
		JSONObject response = new JSONObject();
		response.put("command","SERVER_ANNOUNCE");
		response.put("id",serverId);
		String load = Integer.toString(conToClient.size());
		response.put("load",load);
		response.put("hostname",Settings.getLocalHostname() );
		response.put("port",Settings.getLocalPort()+"");
		
		for(Connection c : conToSer){
			c.writeMsg(response.toString());
		}

		return false;
	}
    
	public boolean authenticate(Connection con, JSONObject msg){
		
		Object temp = msg.get("secret");
		String secret = temp.toString();
		
		if(secret.equals(Settings.getSecret())){
			if(!conToSer.contains(con)){
				//key the log
				conToSer.add(con);
				return false;
			}
			else{
				return invalidMessage(con,"authenticate already");
			}
		}
		else{
			return failMessage(con,"AUTHENTICATION_FAIL","the supplied secret is incorrect:"+secret);
		}
	}
	
	
	public boolean login(Connection con, JSONObject msg){
		
		Object username = msg.get("username");
		Object secret = msg.get("secret");
		
		String usernameS = username.toString();
		String secretS = secret.toString();
		
		if(loginLog.containsValue(usernameS)){
			return failMessage(con,"LOGIN_FALLED","already login in");
		}
		
		//if there exist such user
		if(clientRecord.containsKey(usernameS)){
			if(clientRecord.get(usernameS).equals(secretS)){
				// if the server with least load has 2 clients less than this server 
				if(!freeServer.isEmpty()){
					if((conToClient.size() - Integer.parseInt(freeServer.get("load")) + 1) > 2){
						
						successMessage(con,"LOGIN_SUCCESS","logged in as user  "+ usernameS);
						return redirect(con,"REDIRECT",Integer.parseInt(freeServer.get("load")));
						
					}
				}
				conToClient.add(con);
				loginLog.put(con, usernameS);
				return successMessage(con,"LOGIN_SUCCESS","logged in as user  "+ usernameS);
			}
			else{
				return failMessage(con,"LOGIN_FALLED","secret not match");
			}
		}
		else{
			return failMessage(con,"LOGIN_FALLED","username no found");
		}
		
	}
	
	public boolean activityMessage(Connection con, JSONObject msg){
		
		Object username = msg.get("username");
		Object secret = msg.get("secret");
		JSONObject activity = (JSONObject) msg.get("activity");
		
		String usernameS = username.toString();
		String secretS = secret.toString();
		
		if(clientRecord.containsKey(usernameS)&&clientRecord.get(usernameS).equals(secretS)){
			
			JSONObject response = new JSONObject();
			response.put("command","ACTIVITY_BROADCAST");
			//response.put("authenticated_user", usernameS);
			activity.put("authenticated_user", usernameS);
			String activityS = activity.toString();
			response.put("activity",activityS);
			
			//broadcast to every server
			for(Connection c : conToSer){
				c.writeMsg(response.toString());
			}
			
			//broadcast to every client(no including the one send this act)
			for(Connection c : conToClient){
				if(!c.equals(con)){
					c.writeMsg(response.toString());
				}
			}
			
			return false;
		}
		else{
			return failMessage(con,"AUTHENTICATION_FALL","no authreise");
		}
	}
	
	public boolean serverAnnounce(Connection con, JSONObject msg){
		
		if(!conToSer.contains(con)){
			invalidMessage(con,"recive boardcast from non-authourised server");
			return true;
		}
		
		// record the sever who has the least load
		if(freeServer.isEmpty()){
			freeServer = (HashMap<String,String>)msg;
		}
		if(Integer.parseInt(freeServer.get("load")) > Integer.parseInt(msg.get("load").toString())){
			freeServer = (HashMap<String,String>)msg;
		}
		//keep the record of serverID 
		Object id = msg.get("id");
		String idS = id.toString();
		
		if(!serverIdSet.contains(idS)){
			serverIdSet.add(idS);
		}
		
		for(Connection c : conToSer){
			if(!c.equals(con)){
			c.writeMsg(msg.toString());
			}
		}
		
		return false;
	}
	
	public boolean activityBroadcast(Connection con, JSONObject msg){
		
		if(!conToSer.contains(con)){
			
			invalidMessage(con,"recive boardcast from non-au server");
			return true;
		}
		
		for(Connection c : conToSer){
			if(!c.equals(con)){
				c.writeMsg(msg.toString());
			}
		}
		
		for(Connection c : conToClient){
			c.writeMsg(msg.toString());
		}
		
		return false;
	}
	
	public boolean logOut(Connection con, JSONObject msg){
		return true;
	}
	

	public boolean invalidMessage(Connection con,String info){
		
		JSONObject response = new JSONObject();
		response.put("command","INVALID_MESSAGE");
		response.put("info",info);
		con.writeMsg(response.toString());
		return true;
	}
	
	public boolean failMessage(Connection con,String fail,String info){
		
		JSONObject response = new JSONObject();
		response.put("command",fail);
		response.put("info",info);
		con.writeMsg(response.toString());
		return true;
	}
	
	public boolean successMessage(Connection con,String success,String info){
		
		JSONObject response = new JSONObject();
		response.put("command",success);
		response.put("info",info);
		con.writeMsg(response.toString());
		return false;
	}

	// redirect method
	public boolean redirect(Connection con,String redirect,int leastLoad){
		JSONObject response = new JSONObject();
		// send redirect command
		String hostname = freeServer.get("hostname");
		String port = freeServer.get("port"); 
		response.put("command",redirect);
		response.put("hostname",hostname);
		response.put("port",port);
		con.writeMsg(response.toString());
		return true;
	}
	
	
	public boolean register(Connection con, JSONObject msg){
		
		//if client login already
		if(conToClient.contains(con)){
			return invalidMessage(con,"logined client");
		}
		
		//get part of message 
		Object username = msg.get("username");
		Object secret = msg.get("secret");
		
		String usernameS = username.toString();
		String secretS = secret.toString();
		
		//if username and password exist in this server
		if(clientRecord.containsKey(usernameS)){
			
			return failMessage(con,"REGISTER_FALLED",usernameS + " is already registered with the system");
			
		}
		else{
			
			clientRecord.put(usernameS, secretS);
			
			if(conToSer.size()>0){
			HashSet<String> temp = (HashSet<String>) serverIdSet.clone();
			registerLog.put(usernameS, con);
			lockAllowReply.put(con, temp);
			
			//send lock request
			JSONObject response = new JSONObject();
			response.put("command","LOCK_REQUEST");
			response.put("username",usernameS);
			response.put("secret",secretS);
			//con.writeMsg(response.toString());
			
			for(Connection c : conToSer){
				c.writeMsg(response.toString());				
			}
			
			}
			else{
				return successMessage(con,"REGISTER_SUCCESS","register success for" + usernameS);
			}
			return false;
		}
		
	}

	public boolean lockRequest(Connection con, JSONObject msg){
		
		if(!conToSer.contains(con)){
			return invalidMessage(con,"unau server");
		}
		
		Object username = msg.get("username");
		Object secret = msg.get("secret");
		
		String usernameS = username.toString();
		String secretS = secret.toString();
		
		for(Connection c : conToSer){
			if(!c.equals(con)){
				c.writeMsg(msg.toString());
			}
		}
		
		if(clientRecord.containsKey(usernameS)){
			//lock denied
			JSONObject response = new JSONObject();
			response.put("command","LOCK_DENIED");
			response.put("username",usernameS);
			response.put("secret",secretS);
			
			for(Connection c: conToSer){
				c.writeMsg(response.toString());
			}
			return false;
		}
		else{
			//lock allowd
			clientRecord.put(usernameS,secretS);
			JSONObject response = new JSONObject();
			response.put("command","LOCK_ALLOWED");
			response.put("username",usernameS);
			response.put("secret",secretS);
			response.put("server",serverId );
			
			for(Connection c: conToSer){
				c.writeMsg(response.toString());
			}
			return false;
		}
	}
	
	
	public boolean lockDenied(Connection con, JSONObject msg){
		
		if(!conToSer.contains(con)){
			return invalidMessage(con,"unau server");
		}
		
		for(Connection c : conToSer){
			if(!c.equals(con)){
			c.writeMsg(msg.toString());}
		}
		
		Object username = msg.get("username");
		Object secret = msg.get("secret");
		
		String usernameS = username.toString();
		String secretS = secret.toString();
		
		clientRecord.remove(usernameS);
		
		if(registerLog.containsKey(usernameS)){
			
			failMessage(registerLog.get(usernameS),"REGISTER_FALLED",usernameS + "is already registered with the system");
			lockAllowReply.remove(registerLog.get(usernameS));
			registerLog.remove(usernameS);
			return true;
		}
		
		return false;
	}
	
	
	public boolean lockAllowed(Connection con, JSONObject msg){
		
		if(!conToSer.contains(con)){
			return invalidMessage(con,"unau server");
		}
		
		for(Connection c : conToSer){
			if(!c.equals(con)){
			c.writeMsg(msg.toString());}
		}
		
		Object username = msg.get("username");
		Object secret = msg.get("secret");
		Object id = msg.get("server"); 
		
		String usernameS = username.toString();
		String secretS = secret.toString();
		String idS = id.toString();
		
		if(registerLog.containsKey(usernameS)){
			
			(lockAllowReply.get(registerLog.get(usernameS))).remove(idS);
			HashSet<String> tempIdSet = lockAllowReply.get(registerLog.get(usernameS));
			
			if(tempIdSet.isEmpty()){
				
				successMessage(registerLog.get(usernameS),"REGISTER_SUCCESS","register success for" + usernameS);
				lockAllowReply.remove(registerLog.get(usernameS));
				registerLog.remove(usernameS);
				return false;
			}
		}
		
		return false;
	}

}
