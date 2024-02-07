package org.example;

import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Client {


    //hopefully obvious again
    private static PrivateKey prvClientKey;
    private static PublicKey pubClientKey;
    private static PublicKey pubServerKey;


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


        try{
            //reading client private key
            String path = args[2] + ".prv";
            File f = new File(path);
            byte[] keyBytes = Files.readAllBytes(f.toPath());
            PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            prvClientKey = kf.generatePrivate(prvSpec);

            //reading client public key
            path = args[2] + ".pub";
            f = new File(path);
            keyBytes = Files.readAllBytes(f.toPath());
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
            kf = KeyFactory.getInstance("RSA");
            pubClientKey = kf.generatePublic(pubSpec);

            //reading server public key
            f = new File("server.pub");
            keyBytes = Files.readAllBytes(f.toPath());
            pubSpec = new X509EncodedKeySpec(keyBytes);
            kf = KeyFactory.getInstance("RSA");
            pubServerKey = kf.generatePublic(pubSpec);


            //print for debugging remove later
//            System.out.println(pubClientKey);
//            System.out.println(prvClientKey);
//            System.out.println(pubServerKey);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (Exception e){
            System.err.println("Cannot read Client keys");
        }

        //attempt to establish connection to server with provided details
        try {
            //creating socket
            Socket s = new Socket(host, port);

            //hashing uid to hex
            String secretstring = "gfhk2024:"+args[2]; // secret string
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(secretstring.getBytes());
            byte[] digest = md.digest();
            String uidHex = bytesToString(digest);


            //sending uid to server
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());
            dos.writeUTF(uidHex);

            //receiving reply from server
            DataInputStream dis = new DataInputStream(s.getInputStream());
            String reply = dis.readUTF();
            System.out.println("there are " +reply+" messages to be received");
            for (int i = 0; i < (Integer.parseInt(reply)); i++) {
                //receiving encrypted message from server
                String ts = dis.readUTF();
                String encMessage = dis.readUTF();
                String signatureString = dis.readUTF();

                //TODO:print for debugging remove later
//                System.out.println("Timestamp: " + ts);
//                System.out.println("Encrypted Message: " + encMessage);
//                System.out.println("Signature: " + signatureString);

                //verify signature
                byte[] signatureBytes = stringToBytes(signatureString);
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(pubServerKey);
                sig.update((ts+encMessage).getBytes());
                if (sig.verify(signatureBytes)) {
                    System.out.println("Signature verified");
                } else {
                    System.out.println("Signature verification failed");
                    break;
                }

                //decryption of message
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, prvClientKey);

                byte[] decryptedMessage = cipher.doFinal(stringToBytes(encMessage));


                String decryptedMessageString = new String(decryptedMessage);
                System.out.println("Timestamp: " + ts);
                System.out.println("Decrypted Message: " + decryptedMessageString);

            }
            System.out.println("All messages verified");



            System.out.println("Would you like to send a message? (y/n)");


            //TODO: add send encrypted message functionality here then terminate client


        } catch (Exception e) {
            System.err.println("Cannot connect to server.");
            System.err.println(e);
        }
    }


    //copied from Server class

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

