package org.example;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Client {


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
            System.out.println(pubClientKey);
            System.out.println(prvClientKey);
            System.out.println(pubServerKey);

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
            String uidHex = bytesToHexString(digest);


            //sending uid to server
            DataOutputStream dos = new DataOutputStream(s.getOutputStream());
            dos.writeUTF(uidHex);

            //receiving reply from server
            DataInputStream dis = new DataInputStream(s.getInputStream());
            String reply = dis.readUTF();
            System.out.println(reply);
            for (int i = 0; i < (Integer.parseInt(reply)); i++) {
                //receiving encrypted message from server
                String ts = dis.readUTF();
                String encMessage = dis.readUTF();
                String signatureString = dis.readUTF();

                //print for debugging remove later
                System.out.println("Timestamp: " + ts);
                System.out.println("Encrypted Message: " + encMessage);
                System.out.println("Signature: " + signatureString);

                //verify signature
                byte[] signatureBytes = hexStringToByteArray(signatureString);
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(pubServerKey);
                sig.update((ts+encMessage).getBytes());
                if (sig.verify(signatureBytes)) {
                    System.out.println("Signature verified");
                } else {
                    System.out.println("Signature verification failed");
                    break;
                }
            }
        } catch (Exception e) {
            System.err.println("Cannot connect to server.");
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
