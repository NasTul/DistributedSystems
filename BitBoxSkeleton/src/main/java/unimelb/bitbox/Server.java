package unimelb.bitbox;

import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.net.ServerSocketFactory;
import javax.sql.DataSource;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import unimelb.bitbox.util.*;

import static unimelb.bitbox.ServerMain.HANDSHAKE_REQUEST;
import static unimelb.bitbox.ServerMain.connected_peers;
import static unimelb.bitbox.generateAesKey.getRandom16;
import static unimelb.bitbox.util.PeersPool.clients;
import static unimelb.bitbox.util.PeersPool.peersPool;

public class Server implements Runnable {

    // Declare the port number
    private static int port = 3000;
    static final int TIMEOUT = Integer.parseInt(Configuration.getConfigurationValue("udpTimeout"));  //设置接收数据的超时时间
    static final int MAXNUM = Integer.parseInt(Configuration.getConfigurationValue("udpRetries"));      //设置重发数据的最多次数
    // Identifies the user number connected
    private static int counter = 0;

    public void run() {

        port = Integer.parseInt(Configuration.getConfigurationValue("clientPort"));
        ServerSocketFactory factory = ServerSocketFactory.getDefault();
        try (ServerSocket server = factory.createServerSocket(port)) {
            System.out.println("ServerClint Waiting for client connection..");

            // Wait for connections.
            while (true) {
                Socket client = server.accept();
                counter++;
                System.out.println("Client " + counter + ": Applying for connection!");

                // Start a new thread for a connection
                Thread t = new Thread(() -> serveClient(client));
                t.start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    private static void serveClient(Socket client) {
        String AESKey = "";

        try (Socket clientSocket = client) {

            // The JSON Parser
            JSONParser parser = new JSONParser();
            // Input stream
            DataInputStream input = new DataInputStream(clientSocket.
                    getInputStream());
            // Output Stream
            DataOutputStream output = new DataOutputStream(clientSocket.
                    getOutputStream());
            //System.out.println("From CLIENT: "+input.readUTF());
            JSONObject command = (JSONObject) parser.parse(input.readUTF());
            // System.out.println("serveClient");
            String com = command.get("command").toString();
            // System.out.println("serveClient");
            //   System.out.println(com);
            // System.out.println("serveClient1");

            switch (com) {
                case "AUTH_REQUEST":
                    System.out.println("AUTH_REQUEST");
                    String mypublicKey = Configuration.getConfigurationValue("authorized_keys");
                    String listOfpublicKey[] = mypublicKey.split(",");
                    String peerKey;
                    String peerspublicKey = "";
                    //String arr[] = key.split(" ");
                    String identity = command.get("identity").toString();
                    System.out.println("identity = " + identity);
                    //System.out.println("arr1 = "+arr[1]);
                    boolean flag = false;

                    for (String key : listOfpublicKey) {
                        String findPublicKeyValue = key.split(" ")[1];
                        String findPublicKeyid = key.split(" ")[2];
                        if (identity.equals(findPublicKeyid)) {
                            flag = true;
                            peerspublicKey = findPublicKeyValue;
                        }
                    }
                    if (flag) {
                        AESKey = getRandom16();
                        //AESKey="123";
                        //  String encryptData =  encrypt(AESKey,peerspublicKey);
                        System.out.print("AESKey=" + AESKey);
                        PublicKey publicKey = string2PublicKey(peerspublicKey);
                        byte[] content = publicEncrypt(AESKey.getBytes(), publicKey);
                        String encryptData = Base64.getEncoder().encodeToString(content);
                        //String AES128 =  AES.Encrypt(identity,arr[0]);
                        String msg = AUTH_RESPONSE(encryptData, true, "successful").toJson();
                        output.writeUTF(msg);
                        Document msgFromClientDoc = (Document) Document.parse(input.readUTF());
                        String data = msgFromClientDoc.getString("command");
                        String mode = Configuration.getConfigurationValue("mode");
                        System.out.println("get msg:" + data);
                        switch (data) {
                            case "LIST_PEERS_REQUEST":
                                if (mode.equals("tcp")) {
                                    msg = LIST_PEERS_RESPONSE(peersPool()).toJson();
                                    System.out.println(msg);
                                    msg = AES.Encrypt(msg, AESKey);
                                    System.out.println(msg);
                                    msg = PLAYLOAD(msg).toJson();
                                    System.out.println(msg);
                                    output.writeUTF(msg);

                                } else {
                                    // connected_peers.add(new HostPort("haha.com",1234));
                                    Document document = new Document();
                                    document.append("peers", connected_peers);
                                    msg = LIST_PEERS_RESPONSE(PeersPool.docConnectedPeers(connected_peers)).toJson();
                                    System.out.println(msg);
                                    msg = AES.Encrypt(msg, AESKey);
                                    System.out.println(msg);
                                    msg = PLAYLOAD(msg).toJson();
                                    System.out.println(msg);
                                    output.writeUTF(msg);
                                }
                                //System.out.print("aesKey="+aesKey);
                                break;
                            case "DISCONNECT_PEER_REQUEST":
                                String myHost = Configuration.getConfigurationValue("advertisedName");
                                int myPort;
                                String host = msgFromClientDoc.getString("host");
                                int port = Integer.parseInt(msgFromClientDoc.getString("port"));
                                if (mode.equals("tcp")) {
                                    boolean isActive = false;
                                    for (Socket c : clients) {
                                        if (c.getInetAddress().toString().equals(host)) {
                                            isActive = true;
                                            clients.remove(c);
                                        }
                                    }
                                    if (isActive) {
                                        msg = DISCONNECT_PEER_RESPONSE(host, String.valueOf(port), "disconnected from peer", true).toJson();

                                    } else {
                                        msg = DISCONNECT_PEER_RESPONSE(host, String.valueOf(port), "connection not active", false).toJson();
                                    }
                                    msg = AES.Encrypt(msg, AESKey);
                                    msg = PLAYLOAD(msg).toJson();
                                    output.writeUTF(msg);

                                } else {
                                    //connected_peers.add(new HostPort("haha.com",1234));
                                    boolean isActive = false;
                                    for (int j = 0; j < connected_peers.size(); j++) {
                                        HostPort hostPort = connected_peers.get(j);
                                        if (hostPort.host.equals(host)) {
                                            isActive = true;
                                            connected_peers.remove(hostPort);
                                        }

                                    }
                                    if (isActive) {
                                        msg = DISCONNECT_PEER_RESPONSE(host, String.valueOf(port), "disconnected from peer", true).toJson();
                                        System.out.println("is_Active:" + msg);
                                    } else {
                                        msg = DISCONNECT_PEER_RESPONSE(host, String.valueOf(port), "connection not active", false).toJson();
                                    }
                                    msg = AES.Encrypt(msg, AESKey);
                                    msg = PLAYLOAD(msg).toJson();
                                    output.writeUTF(msg);
                                }

                                //System.out.print("aesKey="+aesKey);
                                break;
                            case "CONNECT_PEER_REQUEST":
                                myHost = Configuration.getConfigurationValue("advertisedName");
                                host = msgFromClientDoc.getString("host");
                                port = Integer.parseInt(msgFromClientDoc.getString("port"));
                                if (mode.equals("tcp")) {
                                    try {
                                        Socket client1 = new Socket(host, port);
                                        //set connect timeout
                                        client1.setSoTimeout(50000);
                                        PrintStream output1 = new PrintStream(client1.getOutputStream());
                                        BufferedReader buf = new BufferedReader(new InputStreamReader(client1.getInputStream()));
                                        String strLine = HANDSHAKE_REQUEST(host, port).toJson();
                                        output1.println(strLine);
                                        strLine = buf.readLine();
                                        Document response = Document.parse(strLine);
                                        String getData = response.getString("command");
                                        switch (getData) {
                                            case "HANDSHAKE_RESPONSE":
                                                clients.add(client);
                                                new ServerHandle(client, buf, ServerMain.fileSystemManager, ServerMain.requestQueue);
                                                msg = CONNECT_PEER_RESPONSE(host, String.valueOf(port), "connected to peer", true).toJson();
                                                msg = AES.Encrypt(msg, AESKey);
                                                msg = PLAYLOAD(msg).toJson();
                                                output.writeUTF(msg);
                                                break;

                                            case "CONNECTION_REFUSED":
                                                msg = CONNECT_PEER_RESPONSE(host, String.valueOf(port), "connection failed", false).toJson();
                                                msg = AES.Encrypt(msg, AESKey);
                                                msg = PLAYLOAD(msg).toJson();
                                                output.writeUTF(msg);
                                                break;
                                        }
                                    } catch (IOException e) {
                                        msg = CONNECT_PEER_RESPONSE(host, String.valueOf(port), "connection failed", false).toJson();
                                        msg = AES.Encrypt(msg, AESKey);
                                        msg = PLAYLOAD(msg).toJson();
                                        output.writeUTF(msg);
                                    }


                                } else {
                                    DatagramSocket clientDatagramSocket = new DatagramSocket();
                                    myPort = Integer.parseInt(Configuration.getConfigurationValue("udpPort"));
                                    String str_send = HANDSHAKE_REQUEST(myHost, myPort).toJson();
                                    System.out.println("Server HandShakeAllPeers_UDP:" + str_send);
                                    byte[] buf = new byte[1024];
                                    try {
                                        InetAddress loc = InetAddress.getByName(host);
                                        //Defines the DatagramPacket instance to send data to
                                        DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), loc, port);
                                        //Defines the DatagramPacket instance to receive data
                                        DatagramPacket dp_receive = new DatagramPacket(buf, 1024);
                                        clientDatagramSocket.setSoTimeout(TIMEOUT);              //设置接收数据时阻塞的最长时间
                                        int tries = 0;                         //重发数据的次数
                                        boolean receivedResponse = false;     //是否接收到数据的标志位

                                        //Exit the loop until the data is received or the number of resits reaches a predetermined value
                                        while (!receivedResponse && tries < MAXNUM) {
                                            try {
                                                clientDatagramSocket.send(dp_send);
                                                //Receive data sent back from the server
                                                clientDatagramSocket.receive(dp_receive);
                                                //If the received data is not from the target address, an exception is thrown
                                                if (!dp_receive.getAddress().equals(loc)) {
                                                    throw new IOException("Received packet from an umknown source");
                                                }
                                                //If receive data.Will change the receivedResponse flag bit to true, thereby exiting the loop
                                                receivedResponse = true;
                                            } catch (SocketTimeoutException e) {
                                                //If a block timeout occurs when data is received, resend and reduce the number of resends
                                                tries += 1;
                                                System.out.println("Time out In Clinet-Peer connect," + (MAXNUM - tries) + " more tries...");
                                            } catch (InterruptedIOException e) {
                                                //If a block timeout occurs when data is received, resend and reduce the number of resends
                                                tries += 1;
                                                System.out.println("Time outIn Clinet-Peer connect," + (MAXNUM - tries) + " more tries...");
                                            }
                                        }
                                        if (receivedResponse) {
                                            //If the data is received, it is printed out
                                            System.out.println("client received data from server：");
                                            String str_receive = new String(dp_receive.getData(), 0, dp_receive.getLength());
                                            System.out.println(str_receive);
                                            Document response = Document.parse(str_receive);
                                            String commandData = response.getString("command");

                                            switch (commandData) {
                                                case "HANDSHAKE_RESPONSE":
                                                    Document reviceHostPort_Doc = (Document) response.get("hostPort");
                                                    int recivePort = Math.toIntExact(reviceHostPort_Doc.getLong("port"));
                                                    String reciveHost = reviceHostPort_Doc.getString("host");
                                                    int flag1 = 0;
                                                    for (HostPort peers : connected_peers) {
                                                        if (peers.host.equals(reciveHost)) {
                                                            flag1 = 1;
                                                        }
                                                    }
                                                    if (flag1 == 0) {
                                                        connected_peers.add(new HostPort(reciveHost, recivePort));
                                                    }
                                                    msg = CONNECT_PEER_RESPONSE(host, String.valueOf(port), "connected to peer", true).toJson();
                                                    msg = AES.Encrypt(msg, AESKey);
                                                    msg = PLAYLOAD(msg).toJson();
                                                    output.writeUTF(msg);

                                                    break;
                                                case "CONNECTION_REFUSED":
                                                    receivedResponse = false;

                                                    msg = CONNECT_PEER_RESPONSE(host, String.valueOf(port), "connection failed", false).toJson();
                                                    msg = AES.Encrypt(msg, AESKey);
                                                    msg = PLAYLOAD(msg).toJson();
                                                    output.writeUTF(msg);
                                                    break;
                                            }

                                            dp_receive.setLength(1024);
                                        } else {
                                            //If the data sent back from the server is not available after the MAXNUM data is reissued, print the following information
                                            System.out.println("No response -- give up.");
                                            msg = CONNECT_PEER_RESPONSE(host, String.valueOf(port), "connection failed", false).toJson();
                                            msg = AES.Encrypt(msg, AESKey);
                                            msg = PLAYLOAD(msg).toJson();
                                            output.writeUTF(msg);
                                        }
                                        clientDatagramSocket.close();
                                    } catch (SocketTimeoutException e) {
                                        //System.out.println(e);
                                    } catch (SocketException e) {
                                        //System.out.println(e);
                                    } catch (UnknownHostException e) {
                                        //System.out.println(e);
                                    } catch (IOException e) {
                                        //	System.out.println(e);
                                    }

                                }
                                break;

                                default:
                                    System.out.println("Client send a wrong command");

                                    break;

                        }


                    } else {
                        String msg = AUTH_RESPONSEFail().toJson();
                        output.writeUTF(msg);
                    }
                    break;
                default:
                    break;
            }

        } catch (IOException | ParseException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Document AUTH_RESPONSE(String AES, boolean status, String msg) {
        Document container1 = new Document();
        container1.append("command", "AUTH_RESPONSE");
        container1.append("AES128", AES);
        container1.append("status", status);
        container1.append("message", msg);
        return container1;
    }

    public static Document AUTH_RESPONSEFail() {
        Document container1 = new Document();
        container1.append("command", "AUTH_RESPONSE");
        container1.append("status", false);
        container1.append("message", "public key not found");
        return container1;
    }


    //The Base64 encoded PublicKey is converted into a PublicKey object
    public static PublicKey string2PublicKey(String pubStr) throws Exception {
        byte[] keyBytes = base642Byte(pubStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    //Byte array Base64 encoding
    public static String byte2Base64(byte[] bytes) {
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(bytes);
    }

    //Base64 Encode transbyte arrays
    public static byte[] base642Byte(String base64Key) throws IOException {
        BASE64Decoder decoder = new BASE64Decoder();
        return decoder.decodeBuffer(base64Key);
    }

    //public key encryption
    public static byte[] publicEncrypt(byte[] content, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    public static Document LIST_PEERS_RESPONSE(ArrayList<Document> peers) {
        Document container1 = new Document();
        container1.append("command", "LIST_PEERS_RESPONSE");
        container1.append("peers", peers);
        return container1;
    }


    public static Document PLAYLOAD(String playload) {
        Document container1 = new Document();
        container1.append("payload", playload);
        return container1;
    }


    public static Document CONNECT_PEER_RESPONSE(String host, String port, String msg, boolean status) {
        Document container1 = new Document();
        container1.append("command", "CONNECT_PEER_RESPONSE");
        container1.append("host", host);
        container1.append("port", port);
        container1.append("status", status);
        container1.append("message", msg);
        return container1;
    }

    public static Document DISCONNECT_PEER_RESPONSE(String host, String port, String msg, boolean status) {
        Document container1 = new Document();
        container1.append("command", "DISCONNECT_PEER_RESPONSE");
        container1.append("host", host);
        container1.append("port", port);
        container1.append("status", status);
        container1.append("message", msg);
        return container1;
    }
}
