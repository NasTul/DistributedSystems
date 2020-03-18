package unimelb.bitbox;


import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import unimelb.bitbox.util.CmdLineArgs;
import unimelb.bitbox.util.Configuration;
import unimelb.bitbox.util.Document;
import unimelb.bitbox.util.RSAConfig;

import javax.crypto.Cipher;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static unimelb.bitbox.AES.Decrypt;

public class Client {

    String mypublicKey;

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        String identity = "";
        String aesKey = "";
        String mypublicKey = Configuration.getConfigurationValue("authorized_keys");
        String listOfpublicKey[] = mypublicKey.split(",");
        System.out.println(Base64.getEncoder().encodeToString(listOfpublicKey[0].getBytes()));
        String myPublicKeyValue = listOfpublicKey[0].split(" ")[1];

        CmdLineArgs argsBean = new CmdLineArgs();
        CmdLineParser parser = new CmdLineParser(argsBean);

        String serverHost;
        String funtion = "";
        String peerHost = null;
        String ip = "localhost";
        String port = "10000";
        try {
            //Parse the arguments
            parser.parseArgument(args);

            serverHost = argsBean.getServerHost();
            peerHost = argsBean.getPeerHost();
            ip = serverHost.split(":")[0];
            port = serverHost.split(":")[1];
            funtion = argsBean.getfunction();
            identity = argsBean.getIdentity();
        } catch (CmdLineException e) {

            System.err.println(e.getMessage());

            parser.printUsage(System.err);
        }
        System.out.print("ip:" + ip + " port:" + port);
        try (Socket socket = new Socket(ip, Integer.parseInt(port))) {

            // Output and Input Stream
            DataInputStream input = new DataInputStream(socket.
                    getInputStream());
            DataOutputStream output = new DataOutputStream(socket.
                    getOutputStream());
            String outputStr = AUTH_REQUEST(identity).toJson();
            System.out.print("outputStr:" + outputStr);

            output.writeUTF(outputStr);
            output.flush();

            String result = input.readUTF();
            System.out.println("Received from server: " + result);
            Document fromServer = (Document) Document.parse(result);
            String command = fromServer.getString("command");
            boolean status = false;
            switch (command) {
                case "AUTH_RESPONSE":
                    status = fromServer.getBoolean("status");

                    if (status) {
                        String AES128 = fromServer.getString("AES128");
                        String getPrivate = RSAConfig.getConfigurationValue("privateKey");
                        aesKey = decrypt(AES128, getPrivate);
                        System.out.print("aesKey=" + aesKey);
                    }
                    break;

            }
            if (status) {
                switch (funtion) {
                    case "list_peers":
                        outputStr = LIST_PEERS_REQUEST().toJson();
                        System.out.println("list_peers:" + outputStr);
                        output.writeUTF(outputStr);
                        output.flush();
                        result = input.readUTF();
                        System.out.println("Received from server: " + result);
                        fromServer = (Document) Document.parse(result);
                        command = fromServer.getString("payload");
                        String decode = Decrypt(command, aesKey);
                        System.out.println(decode);
                        fromServer = Document.parse(decode);
                        command = fromServer.getString("command");
                        switch (command) {
                            case "LIST_PEERS_RESPONSE":
                                System.out.print(command);
                                break;
                        }
                        break;

                    case "connect_peer":
                        ip = peerHost.split(":")[0];
                        port = peerHost.split(":")[1];
                        outputStr = CONNECT_PEER_REQUEST(ip, port).toJson();
                        System.out.println("connect_peer:" + outputStr);
                        output.writeUTF(outputStr);
                        output.flush();
                        result = input.readUTF();
                        System.out.println("Received from server: " + result);
                        fromServer = (Document) Document.parse(result);
                        command = fromServer.getString("payload");
                        decode = Decrypt(command, aesKey);
                        System.out.println(decode);
                        break;

                    case "disconnect_peer":
                        ip = peerHost.split(":")[0];
                        port = peerHost.split(":")[1];
                        outputStr = DISCONNECT_PEER_REQUEST(ip, port).toJson();
                        System.out.println("connect_peer:" + outputStr);
                        output.writeUTF(outputStr);
                        output.flush();
                        result = input.readUTF();

                        System.out.println("Received from server: " + result);
                        fromServer = (Document) Document.parse(result);
                        command = fromServer.getString("payload");
                        decode = Decrypt(command, aesKey);
                        System.out.println(decode);
                        break;

                        default:
                            System.out.println("error commond, please check it ");
                            outputStr = ERROR_COMMAND().toJson();
                            output.writeUTF(outputStr);
                            output.flush();

                            break;
                }
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }


    }


    public static Document LIST_PEERS_REQUEST() {
        Document container1 = new Document();
        container1.append("command", "LIST_PEERS_REQUEST");
        return container1;
    }
    public static Document ERROR_COMMAND() {
        Document container1 = new Document();
        container1.append("command", "ERROR");
        container1.append("msg", "Client send a wrong command");
        return container1;
    }

    public static Document AUTH_REQUEST(String identity) {
        Document container1 = new Document();
        container1.append("command", "AUTH_REQUEST");
        container1.append("identity", identity);
        return container1;
    }

    public static Document CONNECT_PEER_REQUEST(String host, String port) {
        Document container1 = new Document();
        container1.append("command", "CONNECT_PEER_REQUEST");
        container1.append("host", host);
        container1.append("port", port);
        return container1;
    }

    public static Document DISCONNECT_PEER_REQUEST(String host, String port) {
        Document container1 = new Document();
        container1.append("command", "DISCONNECT_PEER_REQUEST");
        container1.append("host", host);
        container1.append("port", port);
        return container1;
    }

    /**
     * RSA private key decryption
     *
     * @param str        Encrypted string
     * @param privateKey
     * @return
     * @throws Exception Abnormal information during decryption
     */
    public static String decrypt(String str, String privateKey) throws Exception {
        //64-bit decoded encrypted string
        byte[] inputByte = Base64.getDecoder().decode(str.getBytes("UTF-8"));
        //base64 Encoded private key
        byte[] decoded = Base64.getDecoder().decode(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA decode
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        String outStr = new String(cipher.doFinal(inputByte));
        return outStr;
    }


}
