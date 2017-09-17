package activitystreamer.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class ClientSolution extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSolution clientSolution;
	private TextFrame textFrame;
	
	private JSONParser parser;
	private boolean term = false;
	private Socket clientSocket; 
	private BufferedReader in;
	private OutputStreamWriter out;
	
	// this is a singleton object
	public static ClientSolution getInstance(){
		if(clientSolution==null){
			clientSolution = new ClientSolution();
		}
		return clientSolution;
	}
	
	public ClientSolution(){
		
		//intitialise every parameter
		try {
			parser = new JSONParser();
			clientSocket = new Socket(Settings.getRemoteHostname(), Settings.getRemotePort());
			in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream(), "UTF-8"));
			out = new OutputStreamWriter(clientSocket.getOutputStream(), "UTF-8");
			
			if(Settings.getSecret() == null){
				//try to gennerate a secret
				Settings.setSecret(Settings.nextSecret());
				//show password
				log.info("secret is "+Settings.getSecret());
				//send register request
				JSONObject register = new JSONObject();
				if(Settings.getUsername().equals("anonymous")){
					register.put("command","LOGIN");
					Settings.setSecret("");
				}
				else{
					register.put("command","REGISTER");					
				}
				register.put("username",Settings.getUsername());
				register.put("secret",Settings.getSecret());
				
				send(register);
			}
			else{
				
				//show password
				log.info("secret is "+Settings.getSecret());
				
				//send login request
				JSONObject login = new JSONObject();
				login.put("command","LOGIN");
				login.put("username",Settings.getUsername());
				login.put("secret",Settings.getSecret());
				
				send(login);
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// open the gui
		log.debug("opening the gui");
		textFrame = new TextFrame();
		// start the client's thread
		start();
	}
	
	// called by the gui when the user clicks "send"
	public void sendActivityObject(JSONObject activityObj){
		send(activityObj);
	}
	
	// called by the gui when the user clicks disconnect
	public void disconnect(){
		
		textFrame.setVisible(false);
		JSONObject closeConnection = new JSONObject();
		closeConnection.put("command", "LOGOUT");
		closeConnection.put("info","connection closed by client");
		send(closeConnection);
		Disconnect();
		
	}
	

	// the client's run method, to receive messages
	@Override
	public void run(){
		String received;
		try {
			while(!term && (received = in.readLine()) != null){
				
				JSONObject msg = (JSONObject) parser.parse(received);
				log.debug("   "+msg+"  ");
				textFrame.setOutputText(msg);
				Object command = msg.get("command");
		
				switch(command.toString()){
					
				case "":
					term = invalidMessage("missing command");
					break;
					
				case "LOGIN_SUCCESS":
					break;

				case "REDIRECT":
					redirect(msg);
					break;
					
				case "LOGIN_FAILED":
					break;
				
				case "AUTHENTICATION_FAIL":
					term = true;
					break;
				
				case "REGISTER_FAILED":
					term = true;
					break;
				
				case "REGISTER_SUCCESS":
					sendLogin();
					break;
				
				case "INVALID_MESSAGE":
					term = true;
					break;
				
				case "ACTIVITY_BROADCAST":
					break;
					
				default :
					term = invalidMessage("can't recognise the command");
					break;
				}
			}
			log.info("close connection to " + Settings.getRemoteHostname());
			Disconnect();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void send(JSONObject message){
		try {
			out.write(message.toString()+"\n");
			out.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void Disconnect(){
		try {
			
			term = true;
			textFrame.setVisible(false);
			in.close();
			out.close();
			clientSocket.close();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public boolean invalidMessage(String info){
		
		JSONObject response = new JSONObject();
		response.put("command","INVALID_MESSAGE");
		response.put("info",info);
		send(response);
		return true;
	}
	
	public void sendLogin(){
		
		JSONObject login = new JSONObject();
		login.put("command","LOGIN");
		login.put("username",Settings.getUsername());
		login.put("secret",Settings.getSecret());
		
		send(login);
	}

	// redirect 
	public void redirect(JSONObject msg){
		
			String hostname = msg.get("hostname").toString();
			int port = Integer.parseInt(msg.get("port").toString());
			Settings.setRemoteHostname(hostname);
			Settings.setRemotePort(port);
			
			//Disconnect();
			
			try {
				
				in.close();
				out.close();
				clientSocket.close();
				
				clientSocket = new Socket(Settings.getRemoteHostname(), Settings.getRemotePort());
				in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream(), "UTF-8"));
				out = new OutputStreamWriter(clientSocket.getOutputStream(), "UTF-8");
				sendLogin();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
	}
	
}
