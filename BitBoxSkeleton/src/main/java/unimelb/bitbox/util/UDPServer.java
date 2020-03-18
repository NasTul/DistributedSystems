package unimelb.bitbox.util;

import unimelb.bitbox.Server;
import unimelb.bitbox.ServerMain;

import java.io.IOException;
import java.io.PrintStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

import static java.lang.Math.min;
import static java.lang.Thread.sleep;
import static unimelb.bitbox.ServerMain.connected_peers;
import static unimelb.bitbox.ServerMain.msgList;
import static unimelb.bitbox.util.ServerHandle.FILE_BYTES_RESPONSE;


public class UDPServer implements Runnable {
    public static DatagramSocket ds = null;

    public void run() {
        Document fileDescriptor;
        int maximumIncommingConnections = Integer.parseInt(Configuration.getConfigurationValue("maximumIncommingConnections"));
        String host = Configuration.getConfigurationValue("advertisedName");
        int port = Integer.parseInt(Configuration.getConfigurationValue("udpPort"));
        byte[] buf = new byte[1024];

        try {
            ds = new DatagramSocket(port);
            //Receives the number sent from the client
            DatagramPacket dp_receive = new DatagramPacket(buf, 1024);
            System.out.println("udp server is on，waiting for client to send data");
            boolean f = true;

            Thread t = new Thread(() -> syncInterval());
            t.start();

            while (f) {
                //The server receives data from the client
                ds.receive(dp_receive);
                String str_receive = new String(dp_receive.getData(), 0, dp_receive.getLength());
                System.out.println("server received data from client：" + str_receive);
                Document response = Document.parse(str_receive);
                String command = response.getString("command");
                switch (command) {
                    case "HANDSHAKE_REQUEST":

                        Document reviceHostPort_Doc = (Document) response.get("hostPort");
                        int recivePort = Math.toIntExact(reviceHostPort_Doc.getLong("port"));
                        String reciveHost = reviceHostPort_Doc.getString("host");
                        InetAddress inetAddress = InetAddress.getByName(reciveHost);
                        if (connected_peers.size() < maximumIncommingConnections) {
                            int flag = 0;
                            for (HostPort peer : connected_peers) {
                                if (peer.host.equals(reciveHost)) {
                                    flag = 1;
                                }
                            }
                            if (flag == 0) {
                                connected_peers.add(new HostPort(reciveHost, recivePort));
                            }
                            String str_send = PeersPool.HANDSHAKE_RESPONSE(host, port).toJson();
                            DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, recivePort);
                            ds.send(dp_send);
                            //Since the dp_receive receives data, its internal message length value becomes the number of bytes of the actual received message,
                            //So here you need to reset the dp_receive internal message length to 1024
                            dp_receive.setLength(1024);

                        } else {
                            //Document pools = Document.parse(connected_peers.toString());
                            String str_send = PeersPool.CONNECTION_REFUSED(PeersPool.docConnectedPeers(connected_peers)).toJson();
                            DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, recivePort);
                            ds.send(dp_send);
                            //Since the dp_receive receives data, its internal message length value becomes the number of bytes of the actual received message,
                            //So here you need to reset the dp_receive internal message length to 1024
                            dp_receive.setLength(1024);

                        }

                        //	new ServerHandle(client, buf, fileSystemManager, requestQueue);
                        break;

                    case "CONNECTION_REFUSED":
                        String name = dp_receive.getAddress().getHostAddress() + "HANDSHAKE_REQUEST";
                        //System.out.println("get Send :"+ name );
                        msgList.replace(name, 1);
                        break;

                    case "HANDSHAKE_RESPONSE":
                        name = dp_receive.getAddress().getHostAddress() + "HANDSHAKE_REQUEST";
                        // System.out.println("get Send :"+ name );
                        msgList.replace(name, 1);
                        reviceHostPort_Doc = (Document) response.get("hostPort");
                        recivePort = Math.toIntExact(reviceHostPort_Doc.getLong("port"));
                        reciveHost = reviceHostPort_Doc.getString("host");
                        int flag = 0;
                        for (HostPort peers : connected_peers) {
                            if (peers.host.equals(reciveHost)) {
                                flag = 1;
                            }
                        }
                        if (flag == 0) {
                            connected_peers.add(new HostPort(reciveHost, recivePort));
                        }


                        break;


                    case "FILE_CREATE_REQUEST":
                        fileDescriptor = (Document) response.get("fileDescriptor");
                        String pathName = response.getString("pathName");
                        String md5 = fileDescriptor.getString("md5");
                        long fileSize = fileDescriptor.getLong("fileSize");
                        long lastModified = fileDescriptor.getLong("lastModified");
                        boolean isCreate = ServerMain.fileSystemManager.createFileLoader(pathName, md5, fileSize, lastModified);
                        fileDescriptor = (Document) response.get("fileDescriptor");
                        int blockSize = Integer.parseInt(Configuration.getConfigurationValue("blockSize"));
                        String message = "error";
                        if (isCreate) {
                            message = "ready";
                        }
                        String strLine = ServerHandle.FILE_CREATE_RESPONSE(md5, lastModified, fileSize, pathName, message, isCreate).toJson();
                        String from_peers = dp_receive.getAddress().getHostAddress();
                        int peer_port = 0;
                        for (HostPort hostPort : connected_peers) {
                            if (hostPort.host.equals(from_peers)) {
                                peer_port = hostPort.port;
                            }
                        }
                        if (peer_port == 0) {

                            System.out.println("unknow peers, dont have handshake record");
                            strLine = INVALID_PROTOCOL().toJson();
                            DatagramPacket dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), dp_receive.getPort());
                            ds.send(dp_send);
                            dp_receive.setLength(1024);

                        } else {
                            DatagramPacket dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), peer_port);
                            ds.send(dp_send);
                            dp_receive.setLength(1024);
                            //System.out.println("isCreate"+isCreate);

                            if (isCreate) {
                                try {
                                    if (!ServerMain.fileSystemManager.checkShortcut(pathName)) {
                                        long length = min(fileDescriptor.getLong("fileSize"), blockSize);
                                        strLine = ServerHandle.FILE_BYTES_REQUEST(md5, lastModified, fileSize, pathName, 0, length).toJson();
                                        dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), dp_receive.getPort());
                                        ds.send(dp_send);
                                        System.out.println("strLine" + strLine);
                                        dp_receive.setLength(1024);
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }

                        }

                        break;


                    case "FILE_BYTES_REQUEST":
                        name = dp_receive.getAddress().getHostAddress() + "FILE_CREATE_REQUEST";
                        msgList.replace(name, 1);
                        name = dp_receive.getAddress().getHostAddress() + "FILE_MODIFY_REQUEST";
                        msgList.replace(name, 1);
                        fileDescriptor = (Document) response.get("fileDescriptor");
                        pathName = response.getString("pathName");
                        ByteBuffer byteBuffer = null;
                        md5 = fileDescriptor.getString("md5");
                        fileSize = fileDescriptor.getLong("fileSize");
                        lastModified = fileDescriptor.getLong("lastModified");
                        long position = response.getLong("position");
                        long length = response.getLong("length");
                        blockSize = Integer.parseInt(Configuration.getConfigurationValue("blockSize"));

                        long send_length = min(length, blockSize);
                        from_peers = dp_receive.getAddress().getHostAddress();
                        peer_port = 0;
                        for (HostPort hostPort : connected_peers) {
                            if (hostPort.host.equals(from_peers)) {
                                peer_port = hostPort.port;
                            }
                        }
                        if (peer_port == 0) {
                            System.out.println("unknow peers, dont have handshake record");
                            strLine = INVALID_PROTOCOL().toJson();
                            DatagramPacket dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), dp_receive.getPort());
                            ds.send(dp_send);
                            dp_receive.setLength(1024);

                        } else {
                            boolean isRead = false;
                            byteBuffer = ServerMain.fileSystemManager.readFile(md5, position, send_length);

                            message = "read";
                            if (byteBuffer == null) {
                                isRead = false;
                                message = "not read";
                            }
                            String str = FILE_BYTES_RESPONSE(md5,
                                    lastModified,
                                    fileSize,
                                    pathName,
                                    position,
                                    send_length,
                                    Base64.getEncoder().encodeToString(byteBuffer.array()),
                                    message,
                                    isRead).toJson();
                            //  str = Base64.getEncoder().encodeToString(str.getBytes());
                            DatagramPacket dp_send = new DatagramPacket(str.getBytes(), str.length(), dp_receive.getAddress(), dp_receive.getPort());
                            ds.send(dp_send);
                            dp_receive.setLength(1024);
                        }

                        break;


                    case "FILE_CREATE_RESPONSE":
                        name = dp_receive.getAddress().getHostAddress() + "FILE_CREATE_REQUEST";
                        msgList.replace(name, 1);
                        break;

                    case "FILE_MODIFY_RESPONSE":
                        name = dp_receive.getAddress().getHostAddress() + "FILE_MODIFY_REQUEST";
                        msgList.replace(name, 1);
                        break;

                    case "FILE_BYTES_RESPONSE":
                        try {

                            from_peers = dp_receive.getAddress().getHostAddress();
                            peer_port = 0;
                            for (HostPort hostPort : connected_peers) {
                                if (hostPort.host.equals(from_peers)) {
                                    peer_port = hostPort.port;
                                }
                            }
                            if (peer_port == 0) {
                                System.out.println("unknow peers, dont have handshake record");
                                strLine = INVALID_PROTOCOL().toJson();
                                DatagramPacket dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), dp_receive.getPort());
                                ds.send(dp_send);
                                dp_receive.setLength(1024);

                            } else {

                                pathName = response.getString("pathName");
                                ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(response.getString("content")));
                                ServerMain.fileSystemManager.writeFile(pathName, buffer, response.getLong("position"));
                                if (!ServerMain.fileSystemManager.checkWriteComplete(pathName)) {
                                    int maxLen = Integer.parseInt(Configuration.getConfigurationValue("blockSize"));
                                    Document bytesRequest = new Document();
                                    fileDescriptor = (Document) response.get("fileDescriptor");
                                    md5 = fileDescriptor.getString("md5");
                                    fileSize = fileDescriptor.getLong("fileSize");
                                    lastModified = fileDescriptor.getLong("lastModified");
                                    position = response.getLong("position");
                                    length = min(fileDescriptor.getLong("fileSize") - position, maxLen);
                                    bytesRequest.append("length", length);
                                    String str = ServerHandle.FILE_BYTES_REQUEST(md5, lastModified, fileSize, pathName, position, length).toJson();
                                    // str =  Base64.getEncoder().encodeToString(str.getBytes());
                                    DatagramPacket dp_send = new DatagramPacket(str.getBytes(), str.length(), dp_receive.getAddress(), peer_port);
                                    ds.send(dp_send);
                                    dp_receive.setLength(1024);
                                }

                            }


                        } catch (Exception e) {

                        }
                        break;
                    case "FILE_MODIFY_REQUEST":
                        fileDescriptor = (Document) response.get("fileDescriptor");
                        pathName = response.getString("pathName");
                        fileSize = fileDescriptor.getLong("fileSize");
                        md5 = fileDescriptor.getString("md5");
                        lastModified = fileDescriptor.getLong("lastModified");
                        int maxLen = Integer.parseInt(Configuration.getConfigurationValue("blockSize"));
                        length = min(fileDescriptor.getLong("fileSize"), maxLen);
                        boolean isModifyLoader;
                        message = "error.";
                        from_peers = dp_receive.getAddress().getHostAddress();
                        peer_port = 0;
                        for (HostPort hostPort : connected_peers) {
                            if (hostPort.host.equals(from_peers)) {
                                peer_port = hostPort.port;
                            }
                        }
                        if (peer_port == 0) {
                            System.out.println("unknow peers, dont have handshake record");
                            strLine = INVALID_PROTOCOL().toJson();
                            DatagramPacket dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), dp_receive.getPort());
                            ds.send(dp_send);
                            dp_receive.setLength(1024);

                        } else {
                            isModifyLoader = ServerMain.fileSystemManager.modifyFileLoader(pathName, md5, lastModified);
                            if (isModifyLoader) {
                                message = "ready";
                            }
                            String str = ServerHandle.FILE_MODIFY_RESPONSE(md5, lastModified, fileSize, pathName, message, isModifyLoader).toJson();
                            //str =  Base64.getEncoder().encodeToString(str.getBytes());
                            DatagramPacket dp_send = new DatagramPacket(str.getBytes(), str.length(), dp_receive.getAddress(), dp_receive.getPort());
                            ds.send(dp_send);
                            //dp_receive.setLength(1024);
                            if (isModifyLoader) {
                                if (!ServerMain.fileSystemManager.checkShortcut(pathName)) {
                                    str = ServerHandle.FILE_BYTES_REQUEST(md5, lastModified, fileSize, pathName, 0, length).toJson();
                                    // str =  Base64.getEncoder().encodeToString(str.getBytes());
                                    dp_send = new DatagramPacket(str.getBytes(), str.length(), dp_receive.getAddress(), dp_receive.getPort());
                                    ds.send(dp_send);

                                }
                            }
                            dp_receive.setLength(1024);
                        }

                        break;

                    case "DIRECTORY_DELETE_REQUEST":


                        from_peers = dp_receive.getAddress().getHostAddress();
                        peer_port = 0;
                        for (HostPort hostPort : connected_peers) {
                            if (hostPort.host.equals(from_peers)) {
                                peer_port = hostPort.port;
                            }
                        }
                        if (peer_port == 0) {
                            System.out.println("unknow peers, dont have handshake record");
                            strLine = INVALID_PROTOCOL().toJson();
                            DatagramPacket dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), dp_receive.getPort());
                            ds.send(dp_send);
                            dp_receive.setLength(1024);

                        } else {

                            pathName = response.getString("pathName");
                            message = "error";
                            boolean isDelete = ServerMain.fileSystemManager.deleteDirectory(pathName);
                            if (isDelete) {
                                message = "deleted";
                            }
                            String str = ServerHandle.DIRECTORY_DELETE_RESPONSE(pathName, message, isDelete).toJson();
                            DatagramPacket dp_send = new DatagramPacket(str.getBytes(), str.length(), dp_receive.getAddress(), peer_port);
                            ds.send(dp_send);
                            dp_receive.setLength(1024);

                        }

                        break;

                    case "DIRECTORY_DELETE_RESPONSE":
                        name = dp_receive.getAddress().getHostAddress() + "DIRECTORY_DELETE_REQUEST";
                        // System.out.println("get Send :"+ name );
                        msgList.replace(name, 1);
                        break;

                    case "DIRECTORY_CREATE_REQUEST":
                        from_peers = dp_receive.getAddress().getHostAddress();
                        peer_port = 0;
                        for (HostPort hostPort : connected_peers) {
                            if (hostPort.host.equals(from_peers)) {
                                peer_port = hostPort.port;
                            }
                        }
                        if (peer_port == 0) {
                            System.out.println("unknow peers, dont have handshake record");
                            strLine = INVALID_PROTOCOL().toJson();
                            DatagramPacket dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), dp_receive.getPort());
                            ds.send(dp_send);
                            dp_receive.setLength(1024);

                        } else {
                            pathName = response.getString("pathName");
                            message = "error";
                            boolean ismkdir = ServerMain.fileSystemManager.makeDirectory(pathName);
                            if (ismkdir) {
                                message = "successfull";
                            }
                            String str = ServerHandle.DIRECTORY_CREATE_RESPONSE(pathName, message, ismkdir).toJson();
                            //str =  Base64.getEncoder().encodeToString(str.getBytes());
                            DatagramPacket dp_send = new DatagramPacket(str.getBytes(), str.length(), dp_receive.getAddress(), peer_port);
                            ds.send(dp_send);
                            dp_receive.setLength(1024);
                        }

                        break;

                    case "DIRECTORY_CREATE_RESPONSE":
                        name = dp_receive.getAddress().getHostAddress() + "DIRECTORY_CREATE_REQUEST";
                        // System.out.println("get Send :"+ name );
                        msgList.replace(name, 1);

                        break;
                    case "FILE_DELETE_RESPONSE":
                        name = dp_receive.getAddress().getHostAddress() + "FILE_DELETE_REQUEST";
                        //System.out.println("get Send :"+ name );
                        msgList.replace(name, 1);
                        break;

                    case "FILE_DELETE_REQUEST":

                        from_peers = dp_receive.getAddress().getHostAddress();
                        peer_port = 0;
                        for (HostPort hostPort : connected_peers) {
                            if (hostPort.host.equals(from_peers)) {
                                peer_port = hostPort.port;
                            }
                        }
                        if (peer_port == 0) {
                            System.out.println("unknow peers, dont have handshake record");
                            strLine = INVALID_PROTOCOL().toJson();
                            DatagramPacket dp_send = new DatagramPacket(strLine.getBytes(), strLine.length(), dp_receive.getAddress(), dp_receive.getPort());
                            ds.send(dp_send);
                            dp_receive.setLength(1024);

                        } else {
                            fileDescriptor = (Document) response.get("fileDescriptor");
                            pathName = response.getString("pathName");
                            md5 = fileDescriptor.getString("md5");
                            fileSize = fileDescriptor.getLong("fileSize");
                            lastModified = fileDescriptor.getLong("lastModified");
                            message = "error";
                            boolean isDelete = ServerMain.fileSystemManager.deleteFile(pathName, lastModified, md5);
                            if (isDelete) {
                                message = "deleted";
                            }
                            String str = ServerHandle.FILE_DELETE_RESPONSE(md5, lastModified, fileSize, pathName, message, isDelete).toJson();
                            // str =  Base64.getEncoder().encodeToString(str.getBytes());
                            DatagramPacket dp_send = new DatagramPacket(str.getBytes(), str.length(), dp_receive.getAddress(), peer_port);
                            ds.send(dp_send);
                            dp_receive.setLength(1024);


                        }

                        break;
                }
            }
        } catch (SocketTimeoutException e) {
            // e.printStackTrace();
        } catch (SocketException e) {
            // e.printStackTrace();
        } catch (IOException e) {
            //  e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            //  e.printStackTrace();
        }

    }

    public void syncInterval() {
        int syncInterval = Integer.parseInt(Configuration.getConfigurationValue("syncInterval"));
        while (true) {
            ArrayList<FileSystemManager.FileSystemEvent> fileEvents = ServerMain.fileSystemManager.generateSyncEvents();
            for (FileSystemManager.FileSystemEvent fileSystemEvent : fileEvents) {
                //System.out.println("fileSystemEvent :" + fileSystemEvent.event);
                switch (fileSystemEvent.event) {
                    case FILE_CREATE:
                        String md5 = fileSystemEvent.fileDescriptor.md5;
                        long lastModified = fileSystemEvent.fileDescriptor.lastModified;
                        long fileSize = fileSystemEvent.fileDescriptor.fileSize;
                        String pathName = fileSystemEvent.pathName;
                        //out.println(ServerMain.FILE_CREATE_REQUEST(md5, lastModified, fileSize, pathName).toJson());
                        for (HostPort hostPort : connected_peers) {

                            System.out.println("connected_peers" + hostPort.toString());
                            InetAddress inetAddress = null;
                            try {
                                inetAddress = InetAddress.getByName(hostPort.host);
                            } catch (UnknownHostException e) {
                                e.printStackTrace();
                            }
                            String str_send = ServerMain.FILE_CREATE_REQUEST(md5, lastModified, fileSize, pathName).toJson();
                            DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                            try {
                                UDPServer.ds.send(dp_send);
                            } catch (IOException e) {
                                e.printStackTrace();
                            }

                        }


                        break;
                    case DIRECTORY_CREATE:

                        for (HostPort hostPort : connected_peers) {
                            InetAddress inetAddress = null;
                            try {
                                inetAddress = InetAddress.getByName(hostPort.host);
                                String str_send = ServerMain.DIRECTORY_CREATE_REQUEST(fileSystemEvent.pathName).toJson();
                                DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                                UDPServer.ds.send(dp_send);
                            } catch (UnknownHostException e) {
                                e.printStackTrace();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }

                        break;
                    case FILE_MODIFY:
                        md5 = fileSystemEvent.fileDescriptor.md5;
                        lastModified = fileSystemEvent.fileDescriptor.lastModified;
                        fileSize = fileSystemEvent.fileDescriptor.fileSize;
                        pathName = fileSystemEvent.pathName;
                        for (HostPort hostPort : connected_peers) {
                            InetAddress inetAddress = null;
                            try {
                                inetAddress = InetAddress.getByName(hostPort.host);
                                String str_send = ServerMain.FILE_MODIFY_REQUEST(md5, lastModified, fileSize, pathName).toJson();
                                DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                                UDPServer.ds.send(dp_send);
                            } catch (UnknownHostException e) {
                                e.printStackTrace();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }

                        }


                        break;

                    case FILE_DELETE:
                        md5 = fileSystemEvent.fileDescriptor.md5;
                        lastModified = fileSystemEvent.fileDescriptor.lastModified;
                        fileSize = fileSystemEvent.fileDescriptor.fileSize;
                        pathName = fileSystemEvent.pathName;
                        //out.println(ServerMain.FILE_DELETE_REQUEST(md5, lastModified, fileSize, pathName).toJson());
                        for (HostPort hostPort : connected_peers) {
                            System.out.println("connected_peers" + hostPort.toString());
                            InetAddress inetAddress = null;
                            try {
                                inetAddress = InetAddress.getByName(hostPort.host);
                                String str_send = ServerMain.FILE_DELETE_REQUEST(md5, lastModified, fileSize, pathName).toJson();
                                DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                                UDPServer.ds.send(dp_send);
                            } catch (UnknownHostException e) {
                                e.printStackTrace();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }


                        }


                        break;
                    case DIRECTORY_DELETE:
                        //out.println(ServerMain.DIRECTORY_DELETE_REQUEST(fileSystemEvent.pathName).toJson());
                        for (HostPort hostPort : connected_peers) {
                            InetAddress inetAddress = null;
                            try {
                                inetAddress = InetAddress.getByName(hostPort.host);
                                String str_send = ServerMain.DIRECTORY_DELETE_REQUEST(fileSystemEvent.pathName).toJson();
                                DatagramPacket dp_send = new DatagramPacket(str_send.getBytes(), str_send.length(), inetAddress, hostPort.port);
                                UDPServer.ds.send(dp_send);
                            } catch (UnknownHostException e) {
                                e.printStackTrace();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }


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

    public static Document INVALID_PROTOCOL() {
        Document container1 = new Document();
        container1.append("command", "INVALID_PROTOCOL");
        container1.append("message", "error, need handshake first");
        return container1;
    }
}
