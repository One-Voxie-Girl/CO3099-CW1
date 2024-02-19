package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class Server {
    //TODO: remove sleep deprived comments


    //hopefully obvious
    private static PrivateKey prvServerKey;
    private static PublicKey pubServerKey;

    //messages array structure
    //all values must be strings
    //use bytesToString and stringToByte to convert between byte[] and string
    //messages[i][0] = hashed recipient uid
    //messages[i][1] = encrypted message
    //messages[i][2] = timestamp
    //private static String[][] messages;
    static List<String[]> messages = new ArrayList<String[]>();

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
//            System.out.println(pubServerKey);
//            System.out.println(prvServerKey);

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


                try {
                    int messageCount = 0;
                    for (String[] message : messages) {
                        if (message != null && message[0].equals(uid)) {
                            messageCount++;
                        }
                    }
                    dos.writeUTF(Integer.toString(messageCount));

                    //search for messages
                    for (int i = 0; i < messages.size(); i++) {
                        if (messages.get(i) != null && messages.get(i)[0].equals(uid)) {
                            //send message and timestamp
                            dos.writeUTF(messages.get(i)[2].toString());
                            dos.writeUTF(messages.get(i)[1].toString());
                            //sign message
                            String signatureString = messages.get(i)[2] + messages.get(i)[1];
                            byte[] signature = signatureString.getBytes();
                            Signature sign = Signature.getInstance("SHA256withRSA");
                            sign.initSign(prvServerKey);
                            sign.update(signature);
                            byte[] signatureBytes = sign.sign();
                            //send signature
                            dos.writeUTF(bytesToString(signatureBytes));
                            //remove message from memory
                            messages.set(i, null);
                        }
                    }
                } catch (NullPointerException e) {
                    dos.writeUTF("0");
                }

                //RECEIVE MESSAGE FROM CLIENT

                //Read in all data sent to server
                String encMsg = dis.readUTF();
                String msgTs = dis.readUTF();
                String msgSig = dis.readUTF();
                String senderUid = dis.readUTF();

                //Get sender public key
                File f = new File(senderUid + ".pub");
                byte[] keyBytes = Files.readAllBytes(f.toPath());
                X509EncodedKeySpec senderPubSpec = new X509EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey senderPubKey = kf.generatePublic(senderPubSpec);

                //Verify message signature
                byte[] signatureBytes = stringToBytes(msgSig);
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(senderPubKey);
                sig.update((encMsg + msgTs).getBytes());
                if (sig.verify(signatureBytes)) {
                    System.out.println("Signature verified");

                    //Decrypt message
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.DECRYPT_MODE, prvServerKey);
                    byte[] decryptedMessage = cipher.doFinal(stringToBytes(encMsg));
                    String decryptedMessageString = new String(decryptedMessage);

                    //Split message into uid and message contents
                    List<String> seperatedMsg = Arrays.asList(decryptedMessageString.split(","));
                    String recipientUid = seperatedMsg.get(0);

                    //Get recipients public key
                    f = new File(recipientUid + ".pub");
                    keyBytes = Files.readAllBytes(f.toPath());
                    X509EncodedKeySpec recipientPubSpec = new X509EncodedKeySpec(keyBytes);
                    PublicKey recipientPubKey = kf.generatePublic(recipientPubSpec);

                    //Re-encrypt message contents for recipient
                    cipher.init(Cipher.ENCRYPT_MODE, recipientPubKey);
                    byte[] encryptedMessage = cipher.doFinal(seperatedMsg.get(1).getBytes());
                    String msgString = bytesToString(encryptedMessage);

                    //Get hash of recipient uid
                    String secretstring = "gfhk2024:" + recipientUid;
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    md.update(secretstring.getBytes());
                    byte[] digest = md.digest();
                    String recipientUidHex = bytesToString(digest);

                    //Save message
                    messages.add(new String[]{recipientUidHex, msgString, msgTs});

                } else {
                    System.out.println("Signature verification failed, discarding");
                }


            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidKeySpecException |
                     NoSuchPaddingException | IllegalBlockSizeException |
                     BadPaddingException e) {//catch literally everything
                throw new RuntimeException(e);
            } 
        }
    }


    public static String bytesToString(byte[] b) {
        byte[] b2 = new byte[b.length + 1];
        b2[0] = 1;
        System.arraycopy(b, 0, b2, 1, b.length);
        return new BigInteger(b2).toString(36);
    }

    public static byte[] stringToBytes(String s) {
        byte[] b2 = new BigInteger(s, 36).toByteArray();
        return Arrays.copyOfRange(b2, 1, b2.length);
    }
}



