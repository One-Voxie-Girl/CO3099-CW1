package org.example;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String[] args) throws IOException {
        System.out.println("hello world");


        //fetching port from command line arguments
        int port = 0;
        try{
            port = Integer.parseInt(args[0]); // port of server
        } catch (NumberFormatException e) {
            System.err.println("Port must be an integer.");
        }

        //starting server
        try{
            ServerSocket ss = new ServerSocket(port);
            System.out.println("Waiting incoming connection...");
            Socket s = ss.accept();


        } catch (Exception e) {
            System.err.println("Cannot start server");
        }

    }


}
