package org.example;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

public class Server {

    private static PrivateKey prvServerKey;
    private static PublicKey pubServerKey;
    private static String[][] messages;

    public static void main(String[] args) throws IOException {




        //fetching port from command line arguments
        int port = 0;
        try{
            port = Integer.parseInt(args[0]); // port of server
        } catch (NumberFormatException e) {
            System.err.println("Port must be an integer.");
        }

        try{
            //reading server private key
            File f = new File("server.prv");
            byte[] keyBytes = Files.readAllBytes(f.toPath());
            PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            prvServerKey = kf.generatePrivate(prvSpec);

            //reading server public key
            f = new File("server.pub");
            keyBytes = Files.readAllBytes(f.toPath());
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
            kf = KeyFactory.getInstance("RSA");
            pubServerKey = kf.generatePublic(pubSpec);


            //print for debugging remove later
            System.out.println(pubServerKey);
            System.out.println(prvServerKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (Exception e){
            System.err.println("Cannot read server keys");
        }
        //starting server

        try{
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Waiting incoming connection...");
            while (true) {
                new ClientHandler(serverSocket.accept()).start();
            }
        } catch (Exception e) {
            System.err.println("Cannot start server");
            System.err.println(e.getMessage());

        }



    }

    private static class ClientHandler extends Thread {
        private Socket clientSocket;

        private String uid;


        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        public void run() {
            try {
                DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
                DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
                String readData = null;
                readData = dis.readUTF();
                String uid = readData;
                System.out.println(readData);
                messages = new String[1][3];
                messages[0] = new String[]{uid, "Hello", "2021-10-10 10:10:10"};
                try {
                    int messageCount = 0;
                    for (int i = 0; i < messages.length; i++) {
                        if (messages[i] != null && messages[i][0].equals(uid)) {
                            messageCount++;
                        }
                    }
                    dos.writeUTF(Integer.toString(messageCount));

                    //search for messages
                    for (int i = 0; i < messages.length; i++) {
                        if (messages[i] != null && messages[i][0].equals(uid)) {
                            //send message and timestamp
                            dos.writeUTF(messages[i][2].toString());
                            dos.writeUTF(messages[i][1].toString());
                            //sign message
                            String signatureString  =  messages[i][2]+ messages[i][1];
                            byte[] signature = signatureString.getBytes();
                            Signature sign = Signature.getInstance("SHA256withRSA");
                            sign.initSign(prvServerKey);
                            sign.update(signature);
                            byte[] signatureBytes = sign.sign();
                            //send signature
                            dos.writeUTF(bytesToHexString(signatureBytes));
                            //remove message from memory
                            messages[i] = null;
                        }
                    }
                } catch (NullPointerException e) {
                    dos.writeUTF("0");
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new RuntimeException(e);
            }
        }
    }





    public static String bytesToHexString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02X", x));
        }
        return sb.toString();
    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] b = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            b[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return b;
    }


}

