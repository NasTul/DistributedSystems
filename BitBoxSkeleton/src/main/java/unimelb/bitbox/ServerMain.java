package unimelb.bitbox;

import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.concurrent.LinkedBlockingQueue;

import unimelb.bitbox.util.*;
import unimelb.bitbox.util.FileSystemManager.FileSystemEvent;
import unimelb.bitbox.util.UDPServer;

import static java.lang.Thread.sleep;
import static unimelb.bitbox.util.UDPServer.ds;


public class ServerMain implements FileSystemObserver {
    private static Logger log = Logger.getLogger(ServerMain.class.getName());
    public static FileSystemManager fileSystemManager;
    private int connectionCount = 0;
    public static Map msgList = new HashMap();
    /*
    LinkedBlockingQueue<Document>
    The LinkedBlockingQueue class implements the BlockingQueue interface.
    Read the BlockingQueue text for more information about the interface.
    The LinkedBlockingQueue keeps the elements internally in a linked structure (linked nodes).
    This linked structure can optionally have an upper bound if desired.
    If no upper bound is specified, Integer.MAX_VALUE is used as the upper bound.
    The LinkedBlockingQueue stores the elements internally in FIFO (First In, First Out) order.
    The head of the queue is the element which has been in queue the longest time,
    and the tail of the queue is the element which has been in the queue the shortest time.
     */
    public static LinkedBlockingQueue<Document> requestQueue = new LinkedBlockingQueue<>();
    public LinkedBlockingQueue<Document> UDP_requestQueue = new LinkedBlockingQueue<>();
    private ArrayList<HostPort> peersList = new ArrayList<>();
    public static ArrayList<HostPort> connected_peers = new ArrayList<>();
    private ArrayList<Socket> clients = new ArrayList<>();
    private PeersPool peersPool = null;
    private ClientHandle clientHandle = null;
    private String host;
    private int port;
    private Integer maximumIncommingConnections;
    private DatagramSocket clientDatagramSocket;
    String mode;
    final int TIMEOUT = Integer.parseInt(Configuration.getConfigurationValue("udpTimeout"));  //设置接收数据的超时时间
    final int MAXNUM = Integer.parseInt(Configuration.getConfigurationValue("udpRetries"));      //设置重发数据的最多次数
    String myHost = Configuration.getConfigurationValue("advertisedName");
    int myPort;

    public ServerMain() throws NumberFormatException, IOException, NoSuchAlgorithmException {
        fileSystemManager = new FileSystemManager(Configuration.getConfigurationValue("path"), this);
        maximumIncommingConnections = Integer.parseInt(Configuration.getConfigurationValue("maximumIncommingConnections"));
        mode = Configuration.getConfigurationValue("mode");
        String peersToString = Configuration.getConfigurationValue("peers");
        String[] str = peersToString.split(",");
        for (int i = 0; i < str.length; i++) {
            host = str[i].split(":")[0];
            port = Integer.parseInt(str[i].split(":")[1]);
            peersList.add(new HostPort(host, port));
        }

        if (mode.equals("tcp")) {
            myPort = Integer.parseInt(Configuration.getConfigurationValue("port"));
            peersPool = new PeersPool(fileSystemManager, requestQueue);
            for (HostPort peer : peersList) {
                HandShakeAllPeers_TCP(peer);
                clientHandle = new ClientHandle(clients, requestQueue, this.peersPool);
            }
        } else {
            //System.out.println("udp");
            new Thread(new UDPServer()).start();

            myPort = Integer.parseInt(Configuration.getConfigurationValue("udpPort"));
            clientDatagramSocket = ds;
            for (HostPort peer : peersList) {

                HandShakeAllPeers_UDP(peer);

            }

        }

    }


    private void HandShakeAllPeers_TCP(HostPort peer) {
        String host = peer.host;
        int port = peer.port;

        try {
            Socket client = new Socket(host, port);
            //set connect timeout
            client.setSoTimeout(50000);
            PrintStream output = new PrintStream(client.getOutputStream());
            BufferedReader buf = new BufferedReader(new InputStreamReader(client.getInputStream()));
            String strLine = HANDSHAKE_REQUEST(myHost, myPort).toJson();
            //strLine = Base64.getEncoder().encodeToString(strLine.getBytes());
            //System.out.println("ServerMain - strLine 79:"+strLine);
            System.out.println("send Msg:" + strLine);

            output.println(strLine);

            strLine = buf.readLine();
            //strLine = Base64.getDecoder().decode(strLine.getBytes()).toString();
            //System.out.println("ServerMain - strLine 82:"+strLine);

            Document response = Document.parse(strLine);
            String command = response.getString("command");
            switch (command) {
                case "HANDSHAKE_RESPONSE":
                    clients.add(client);
                    new ServerHandle(client, buf, fileSystemManager, requestQueue);
                    break;
                case "CONNECTION_REFUSED":

                    break;
            }
        } catch (IOException e) {

        }

    }

    private void HandShakeAllPeers_UDP(HostPort peer) {
        String host = peer.host;
        int port = peer.port;

        String str_send = HANDSHAKE_REQUEST(myHost, myPort).toJson();
        System.out.println("Server HandShakeAllPeers_UDP:" + str_send);
        byte[] buf = new byte[1024];
        try {
            InetAddress loc = InetAddress.getByName(host);
            DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), loc, port);
            Thread t = new Thread(() -> send_msg(dp_send, host, "HANDSHAKE_REQUEST"));
            t.start();

        }

        catch (UnknownHostException e) {
            //System.out.println(e);
        } catch (IOException e) {
            //	System.out.println(e);
        }


    }


    @Override
    public void processFileSystemEvent(FileSystemEvent fileSystemEvent) throws IOException {

        switch (fileSystemEvent.event) {
            case FILE_CREATE:
                String md5 = fileSystemEvent.fileDescriptor.md5;
                long lastModified = fileSystemEvent.fileDescriptor.lastModified;
                long fileSize = fileSystemEvent.fileDescriptor.fileSize;
                String pathName = fileSystemEvent.pathName;
                if (mode.equals("tcp")) {
                    try {
                        requestQueue.put(FILE_CREATE_REQUEST(md5, lastModified, fileSize, pathName));
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
//					System.out.println("connected_peers"+connected_peers.get(0).toString());
                    System.out.println(connected_peers.size());

                    for (HostPort hostPort : connected_peers) {
                        System.out.println("connected_peers" + hostPort.toString());
                        InetAddress inetAddress = InetAddress.getByName(hostPort.host);
                        String str_send = FILE_CREATE_REQUEST(md5, lastModified, fileSize, pathName).toJson();
                        DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);

                        Thread t = new Thread(() -> send_msg(dp_send, hostPort.host, "FILE_CREATE_REQUEST"));
                        t.start();

                    }

                }

                break;


            case FILE_DELETE:
                md5 = fileSystemEvent.fileDescriptor.md5;
                lastModified = fileSystemEvent.fileDescriptor.lastModified;
                fileSize = fileSystemEvent.fileDescriptor.fileSize;
                pathName = fileSystemEvent.pathName;

                if (mode.equals("tcp")) {
                    try {
                        requestQueue.put(FILE_DELETE_REQUEST(md5, lastModified, fileSize, pathName));
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {

                    for (HostPort hostPort : connected_peers) {
                        System.out.println("connected_peers" + hostPort.toString());
                        InetAddress inetAddress = InetAddress.getByName(hostPort.host);
                        String str_send = FILE_DELETE_REQUEST(md5, lastModified, fileSize, pathName).toJson();
                        DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                        Thread t = new Thread(() -> send_msg(dp_send, hostPort.host, "FILE_DELETE_REQUEST"));
                        t.start();

                    }


                }


                break;
            case FILE_MODIFY:

                md5 = fileSystemEvent.fileDescriptor.md5;
                lastModified = fileSystemEvent.fileDescriptor.lastModified;
                fileSize = fileSystemEvent.fileDescriptor.fileSize;
                pathName = fileSystemEvent.pathName;
                if (mode.equals("tcp")) {
                    try {
                        requestQueue.put(FILE_MODIFY_REQUEST(md5, lastModified, fileSize, pathName));
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                } else {
                    for (HostPort hostPort : connected_peers) {
                        InetAddress inetAddress = InetAddress.getByName(hostPort.host);
                        String str_send = FILE_MODIFY_REQUEST(md5, lastModified, fileSize, pathName).toJson();
                        DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                        Thread t = new Thread(() -> send_msg(dp_send, hostPort.host, "FILE_MODIFY_REQUEST"));
                        t.start();
                    }
                }

                break;


            case DIRECTORY_CREATE:
                if (mode.equals("tcp")) {
                    try {
                        requestQueue.put(DIRECTORY_CREATE_REQUEST(fileSystemEvent.pathName));
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                } else {
                    for (HostPort hostPort : connected_peers) {
                        InetAddress inetAddress = InetAddress.getByName(hostPort.host);
                        String str_send = DIRECTORY_CREATE_REQUEST(fileSystemEvent.pathName).toJson();
                        DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                        Thread t = new Thread(() -> send_msg(dp_send, hostPort.host, "DIRECTORY_CREATE_REQUEST"));
                        t.start();
                    }

                }

                break;
            case DIRECTORY_DELETE:
                if (mode.equals("tcp")) {
                    try {
                        requestQueue.put(DIRECTORY_DELETE_REQUEST(fileSystemEvent.pathName));
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                } else {
                    for (HostPort hostPort : connected_peers) {
                        InetAddress inetAddress = InetAddress.getByName(hostPort.host);
                        String str_send = DIRECTORY_DELETE_REQUEST(fileSystemEvent.pathName).toJson();
                        DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                        Thread t = new Thread(() -> send_msg(dp_send, hostPort.host, "DIRECTORY_DELETE_REQUEST"));
                        t.start();
                    }

                }
                break;
            default:
                System.out.println("error");
                break;
        }
    }

    public static Document HANDSHAKE_REQUEST(String host, int port) {
        Document request = new Document();
        Document hostPort = new Document();
        hostPort.append("host", host);
        hostPort.append("port", port);
        request.append("command", "HANDSHAKE_REQUEST");
        request.append("hostPort", hostPort);
        return request;
    }

    public static Document FILE_CREATE_REQUEST(String fileMd5, long lastModified, long fileSize, String pathName) {
        Document container = new Document();
        container.append("command", "FILE_CREATE_REQUEST");
        Document fileDescriptor = new Document();
        fileDescriptor.append("md5", fileMd5);
        fileDescriptor.append("lastModified", lastModified);
        fileDescriptor.append("fileSize", fileSize);
        container.append("fileDescriptor", fileDescriptor);
        container.append("pathName", pathName);
        return container;
    }

    public static Document FILE_DELETE_REQUEST(String fileMd5, long lastModified, long fileSize, String pathName) {
        Document container = new Document();
        container.append("command", "FILE_DELETE_REQUEST");
        Document fileDescriptor = new Document();
        fileDescriptor.append("md5", fileMd5);
        fileDescriptor.append("lastModified", lastModified);
        fileDescriptor.append("fileSize", fileSize);
        container.append("pathName", pathName);
        container.append("fileDescriptor", fileDescriptor);
        return container;
    }

    public static Document DIRECTORY_CREATE_REQUEST(String pathName) {
        Document container1 = new Document();
        container1.append("command", "DIRECTORY_CREATE_REQUEST");
        container1.append("pathName", pathName);
        return container1;
    }

    public static Document DIRECTORY_DELETE_REQUEST(String pathName) {
        Document container1 = new Document();
        container1.append("command", "DIRECTORY_DELETE_REQUEST");
        container1.append("pathName", pathName);
        return container1;
    }

    public static Document FILE_MODIFY_REQUEST(String fileMd5, long lastModified, long fileSize, String pathName) {
        Document container = new Document();
        container.append("command", "FILE_MODIFY_REQUEST");
        Document fileDescriptor = new Document();
        fileDescriptor.append("md5", fileMd5);
        fileDescriptor.append("lastModified", lastModified);
        fileDescriptor.append("fileSize", fileSize);
        container.append("fileDescriptor", fileDescriptor);
        container.append("pathName", pathName);
        return container;
    }


    void send_msg(DatagramPacket dp_send, String host, String sendMsg) {
        try {
            System.out.println("send msg:" + new String(dp_send.getData()));
            int tries = 0;                         //The number of times the data was reposted
            boolean receivedResponse = false;     //Flag bit whether data was received
            ds.send(dp_send);
            String name = host + sendMsg;
            //System.out.println("send :"+name);
            msgList.put(name, 0);
            sleep(TIMEOUT);
            int isSend = (int) msgList.get(name);
            if (isSend == 1) {
                receivedResponse = true;
            }
            while (!receivedResponse && tries < MAXNUM) {
                ds.send(dp_send);
                isSend = (int) msgList.get(name);
                if (isSend == 1) {
                    receivedResponse = true;
                }
                tries++;
                System.out.println(" re try send :" + new String(dp_send.getData()));
                sleep(TIMEOUT);
            }
            if (receivedResponse) {
                System.out.println("got msg dont need to re try");

            } else {
                System.out.println("TIMEOUT");
            }

        } catch (IOException e) {
            //e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

}
