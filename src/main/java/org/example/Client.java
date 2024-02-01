package org.example;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;

public class Client {
    public static void main(String[] args) {
        String host = args[0]; // hostname of server
        int port = 0;           // port of server

        //fetching port from command line arguments
        try{
            port = Integer.parseInt(args[1]); // port of server
        } catch (NumberFormatException e) {
            System.err.println("Port must be an integer.");
            return;
        }



        //attempt to establish connection to server with provided details
        try {
            Socket s = new Socket(host, port);


        } catch (Exception e) {
            System.err.println("Cannot connect to server.");
        }
    }
}
