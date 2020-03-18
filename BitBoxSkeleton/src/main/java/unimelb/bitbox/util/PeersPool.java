package unimelb.bitbox.util;

import unimelb.bitbox.ServerMain;
import unimelb.bitbox.generateAesKey;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

import static unimelb.bitbox.util.ServerHandle.AUTH_RESPONSE;

public class PeersPool extends Thread {
    private static Logger log = Logger.getLogger(PeersPool.class.getName());
    private int maximumIncommingConnections;
    private int connectionCount = 0;
    private int syncInterval;
    private String host;
    private int port;
    Socket client = null;
    public static String AESKey;

    public static ArrayList<Socket> clients = new ArrayList<>();
    private FileSystemManager fileSystemManager = null;
    private LinkedBlockingQueue<Document> requestQueue;

    public PeersPool(FileSystemManager fileSystemManager, LinkedBlockingQueue<Document> requestQueue) {
        this.maximumIncommingConnections = Integer.parseInt(Configuration.getConfigurationValue("maximumIncommingConnections"));
        this.port = Integer.parseInt(Configuration.getConfigurationValue("port"));
        this.host = Configuration.getConfigurationValue("advertisedName");
        this.fileSystemManager = fileSystemManager;
        this.requestQueue = requestQueue;
        start();
    }

    public void run() {
        try {
            // System.out.println("PeersPool wait");
            int port = Integer.parseInt(Configuration.getConfigurationValue("port"));
            ServerSocket server = new ServerSocket(port);
            while (true) {
                System.out.println("in peer pool while");
                client = server.accept();
                PrintStream out = new PrintStream(client.getOutputStream());
                BufferedReader buf = new BufferedReader(new InputStreamReader(client.getInputStream()));
                String strLine = buf.readLine();
                // System.out.println("in peer pool"+strLine);

                //strLine = Base64.getDecoder().decode(strLine.getBytes()).toString();
                Document request = Document.parse(strLine);
                String command = request.getString("command");
                // System.out.println("PeersPool wait command"+command);

                // valid request
                switch (command) {
                    case "HANDSHAKE_REQUEST":
                        // hand shake request
                        if (connectionCount >= maximumIncommingConnections) {
                            // if there are too many connection, refuse
                            strLine = CONNECTION_REFUSED(peersPool()).toJson();
                            System.out.println("send Msg:" + strLine);
                            //strLine = Base64.getEncoder().encodeToString(strLine.getBytes());
                            out.println(strLine);
                        } else {
                            strLine = HANDSHAKE_RESPONSE(host, port).toJson();
                            // strLine = Base64.getEncoder().encodeToString(strLine.getBytes());
                            System.out.println("PeersPool - strLine 58:" + strLine);
                            out.println(strLine);
                            Thread t = new Thread(() -> syncInterval(out));
                            t.start();
                            clients.add(client);
                            connectionCount += 1;
                            new ServerHandle(client, buf, fileSystemManager, requestQueue);
                        }
                        break;

                    default:
                        strLine = INVALID_PROTOCOL().toJson();
                        //strLine = Base64.getEncoder().encodeToString(strLine.getBytes());
                        out.print(strLine);
                        client.close();
                        break;
                }
            }

        } catch (Exception e) {

        }
    }


    public void syncInterval(PrintStream out) {
        syncInterval = Integer.parseInt(Configuration.getConfigurationValue("syncInterval"));
        while (true) {
            ArrayList<FileSystemManager.FileSystemEvent> fileEvents = fileSystemManager.generateSyncEvents();
            for (FileSystemManager.FileSystemEvent fileSystemEvent : fileEvents) {
                //System.out.println("fileSystemEvent :" + fileSystemEvent.event);

                switch (fileSystemEvent.event) {
                    case FILE_CREATE:
                        String md5 = fileSystemEvent.fileDescriptor.md5;
                        long lastModified = fileSystemEvent.fileDescriptor.lastModified;
                        long fileSize = fileSystemEvent.fileDescriptor.fileSize;
                        String pathName = fileSystemEvent.pathName;
                        out.println(ServerMain.FILE_CREATE_REQUEST(md5, lastModified, fileSize, pathName).toJson());
                        break;
                    case DIRECTORY_CREATE:
                        out.println(ServerMain.DIRECTORY_CREATE_REQUEST(fileSystemEvent.pathName).toJson());
                        break;
                    case FILE_MODIFY:
                        md5 = fileSystemEvent.fileDescriptor.md5;
                        lastModified = fileSystemEvent.fileDescriptor.lastModified;
                        fileSize = fileSystemEvent.fileDescriptor.fileSize;
                        pathName = fileSystemEvent.pathName;
                        out.println(ServerMain.FILE_MODIFY_REQUEST(md5, lastModified, fileSize, pathName).toJson());
                        break;

                    case FILE_DELETE:
                        md5 = fileSystemEvent.fileDescriptor.md5;
                        lastModified = fileSystemEvent.fileDescriptor.lastModified;
                        fileSize = fileSystemEvent.fileDescriptor.fileSize;
                        pathName = fileSystemEvent.pathName;
                        out.println(ServerMain.FILE_DELETE_REQUEST(md5, lastModified, fileSize, pathName).toJson());
                        break;
                    case DIRECTORY_DELETE:
                        out.println(ServerMain.DIRECTORY_DELETE_REQUEST(fileSystemEvent.pathName).toJson());
                        break;

                    default:
                        break;
                }

            }

            try {
                sleep(syncInterval * 1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }


    public static Document HANDSHAKE_RESPONSE(String host, int port) {
        Document container = new Document();
        container.append("command", "HANDSHAKE_RESPONSE");
        Document hostPort = new Document();
        hostPort.append("host", host);
        hostPort.append("port", port);
        container.append("hostPort", hostPort);
        return container;
    }

    public static Document CONNECTION_REFUSED(ArrayList<Document> peersPool) {
        Document container1 = new Document();
        container1.append("command", "CONNECTION_REFUSED");
        container1.append("message", "connection limit reached");
        container1.append("peers", peersPool);
        return container1;
    }

    public static Document INVALID_PROTOCOL() {
        Document container1 = new Document();
        container1.append("command", "INVALID_PROTOCOL");
        container1.append("message", "message must contain a command field as string");
        return container1;
    }

    public static ArrayList<Document> peersPool() {
        ArrayList<Document> peersPool = new ArrayList<>();
        for (Socket client : clients) {
            Document hostPort = new Document();
            hostPort.append("host", client.getInetAddress().toString());
            hostPort.append("port", client.getPort());
            peersPool.add(hostPort);
        }
        return peersPool;
    }

    public static ArrayList<Document> docConnectedPeers(ArrayList<HostPort> connectedPeers) {
        ArrayList<Document> peersPool = new ArrayList<>();
        for (HostPort client : connectedPeers) {
            Document hostPort = new Document();
            hostPort = client.toDoc();
            peersPool.add(hostPort);
        }
        return peersPool;
    }


}
