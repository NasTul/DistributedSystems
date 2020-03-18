package unimelb.bitbox.util;

import unimelb.bitbox.AES;
import unimelb.bitbox.generateAesKey;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.PrintStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

import static java.lang.Math.min;
import static unimelb.bitbox.generateAesKey.getRandom16;

public class ServerHandle extends Thread {
    private static Logger log = Logger.getLogger(ServerHandle.class.getName());
    public Socket client = null;
    private BufferedReader buf = null;
    private FileSystemManager fileSystemManager = null;
    private LinkedBlockingQueue<Document> requestQueue = null;
    String AESKey;

    public ServerHandle(Socket client, BufferedReader buf, FileSystemManager fileSystemManager, LinkedBlockingQueue<Document> requestQueue) {
        this.client = client;
        this.buf = buf;
        this.fileSystemManager = fileSystemManager;
        this.requestQueue = requestQueue;
        start();
    }

    public void run() {
        while (true) {
            try {

                client.setSoTimeout(Integer.MAX_VALUE);
                while (true) {
                    String strLine = buf.readLine();
                    //strLine = Base64.getDecoder().decode(strLine.getBytes()).toString();
                    System.out.println("ServerHandle - getMsg:" + strLine);

                    if (strLine == null) {
                        continue;
                    }
                    Document request = Document.parse(strLine);
                    String command = request.getString("command");

                    if (command == null) {
                        continue;
                    }
                    PrintStream out = new PrintStream(client.getOutputStream());
                    switch (command) {
                        case "FILE_CREATE_REQUEST":
                            Document fileDescriptor = (Document) request.get("fileDescriptor");
                            String pathName = request.getString("pathName");
                            String md5 = fileDescriptor.getString("md5");
                            long fileSize = fileDescriptor.getLong("fileSize");
                            long lastModified = fileDescriptor.getLong("lastModified");
                            boolean isCreate = fileSystemManager.createFileLoader(pathName, md5, fileSize, lastModified);
                            fileDescriptor = (Document) request.get("fileDescriptor");
                            int blockSize = Integer.parseInt(Configuration.getConfigurationValue("blockSize"));

                            String message = "error";
                            if (isCreate) {
                                message = "ready";
                            }
                            strLine = FILE_CREATE_RESPONSE(md5, lastModified, fileSize, pathName, message, isCreate).toJson();
                            //strLine =  Base64.getEncoder().encodeToString(strLine.getBytes());
                            out.println(strLine);
                            if (isCreate) {
                                try {
                                    if (!fileSystemManager.checkShortcut(pathName)) {
                                        long length = min(fileDescriptor.getLong("fileSize"), blockSize);
                                        strLine = FILE_BYTES_REQUEST(md5, lastModified, fileSize, pathName, 0, length).toJson();
                                        //strLine =  Base64.getEncoder().encodeToString(strLine.getBytes());
                                        out.println(strLine);
                                    }
                                } catch (Exception e) {

                                }
                            }
                            break;


                        case "FILE_BYTES_REQUEST":

                            fileDescriptor = (Document) request.get("fileDescriptor");
                            pathName = request.getString("pathName");
                            ByteBuffer byteBuffer = null;
                            md5 = fileDescriptor.getString("md5");
                            fileSize = fileDescriptor.getLong("fileSize");
                            lastModified = fileDescriptor.getLong("lastModified");
                            long position = request.getLong("position");
                            long length = request.getLong("length");
                            boolean isRead = false;
                            byteBuffer = fileSystemManager.readFile(md5, position, length);
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
                                    length,
                                    Base64.getEncoder().encodeToString(byteBuffer.array()),
                                    message,
                                    isRead).toJson();
                            //  str = Base64.getEncoder().encodeToString(str.getBytes());
                            out.println(str);
                            break;


                        case "FILE_BYTES_RESPONSE":
                            try {
                                pathName = request.getString("pathName");
                                ByteBuffer buf = ByteBuffer.wrap(Base64.getDecoder().decode(request.getString("content")));
                                fileSystemManager.writeFile(pathName, buf, request.getLong("position"));
                                if (!fileSystemManager.checkWriteComplete(pathName)) {
                                    int maxLen = Integer.parseInt(Configuration.getConfigurationValue("blockSize"));
                                    Document bytesRequest = new Document();
                                    fileDescriptor = (Document) request.get("fileDescriptor");
                                    md5 = fileDescriptor.getString("md5");
                                    fileSize = fileDescriptor.getLong("fileSize");
                                    lastModified = fileDescriptor.getLong("lastModified");
                                    position = request.getLong("position");
                                    length = min(fileDescriptor.getLong("fileSize") - position, maxLen);
                                    bytesRequest.append("length", length);
                                    str = FILE_BYTES_REQUEST(md5, lastModified, fileSize, pathName, position, length).toJson();
                                    // str =  Base64.getEncoder().encodeToString(str.getBytes());
                                    out.println(str);
                                }

                            } catch (Exception e) {

                            }
                            break;

                        case "FILE_DELETE_REQUEST":
                            fileDescriptor = (Document) request.get("fileDescriptor");
                            pathName = request.getString("pathName");
                            md5 = fileDescriptor.getString("md5");
                            fileSize = fileDescriptor.getLong("fileSize");
                            lastModified = fileDescriptor.getLong("lastModified");
                            boolean isDelete;
                            message = "error";
                            isDelete = fileSystemManager.deleteFile(pathName, lastModified, md5);
                            if (isDelete) {
                                message = "deleted";
                            }
                            str = FILE_DELETE_RESPONSE(md5, lastModified, fileSize, pathName, message, isDelete).toJson();
                            // str =  Base64.getEncoder().encodeToString(str.getBytes());

                            out.println(str);
                            break;

                        case "FILE_MODIFY_REQUEST":
                            fileDescriptor = (Document) request.get("fileDescriptor");
                            pathName = request.getString("pathName");
                            fileSize = fileDescriptor.getLong("fileSize");
                            md5 = fileDescriptor.getString("md5");
                            lastModified = fileDescriptor.getLong("lastModified");
                            int maxLen = Integer.parseInt(Configuration.getConfigurationValue("blockSize"));
                            length = min(fileDescriptor.getLong("fileSize"), maxLen);

                            boolean isModifyLoader;
                            message = "error.";
                            isModifyLoader = fileSystemManager.modifyFileLoader(pathName, md5, lastModified);
                            if (isModifyLoader) {
                                message = "ready";
                            }
                            str = FILE_MODIFY_RESPONSE(md5, lastModified, fileSize, pathName, message, isModifyLoader).toJson();
                            //str =  Base64.getEncoder().encodeToString(str.getBytes());

                            out.println(str);
                            if (isModifyLoader) {
                                if (!fileSystemManager.checkShortcut(pathName)) {
                                    str = FILE_BYTES_REQUEST(md5, lastModified, fileSize, pathName, 0, length).toJson();
                                    // str =  Base64.getEncoder().encodeToString(str.getBytes());

                                    out.println(str);
                                }
                            }
                            break;

                        case "DIRECTORY_CREATE_REQUEST":
                            pathName = request.getString("pathName");
                            message = "error";
                            boolean ismkdir = fileSystemManager.makeDirectory(pathName);
                            if (ismkdir) {
                                message = "successfull";
                            }
                            str = DIRECTORY_CREATE_RESPONSE(pathName, message, ismkdir).toJson();
                            //str =  Base64.getEncoder().encodeToString(str.getBytes());

                            out.println(str);
                            break;

                        case "AUTH_REQUEST":

                            String mypublicKey = Configuration.getConfigurationValue("authorized_keys");
                            String listOfpublicKey[] = mypublicKey.split(",");
                            String peerKey;
                            String peerspublicKey = "";
                            //String arr[] = key.split(" ");
                            String identity = request.getString("identity");
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
                                String encryptData = encrypt(AESKey, peerspublicKey);
                                // String AES128 =  AES.Encrypt(identity,arr[0]);
                                String msg = AUTH_RESPONSE(encryptData, true, "successful").toJson();
                                out.println(msg);
                            } else {

                                String msg = AUTH_RESPONSEFail().toJson();
                                out.println(msg);
                            }
                            break;


                        case "DIRECTORY_DELETE_REQUEST":
                            pathName = request.getString("pathName");
                            message = "error";
                            isDelete = fileSystemManager.deleteDirectory(pathName);
                            if (isDelete) {
                                message = "deleted";
                            }
                            str = DIRECTORY_DELETE_RESPONSE(pathName, message, isDelete).toJson();
                            //str =  Base64.getEncoder().encodeToString(str.getBytes());
                            out.println(str);
                            break;
                        default:
                            break;
                        // log.info("Got:" + request.toJson());

                    }
                }
            } catch (SocketException e) {
                break;
            } catch (Exception e) {
                log.warning(e.getMessage());
            }
        }
    }


    public static Document FILE_CREATE_RESPONSE(String fileMd5, long lastModified, long fileSize, String pathName, String message, Boolean status) {
        Document container = new Document();
        container.append("command", "FILE_CREATE_RESPONSE");
        Document fileDescriptor = new Document();
        fileDescriptor.append("md5", fileMd5);
        fileDescriptor.append("lastModified", lastModified);
        fileDescriptor.append("fileSize", fileSize);
        container.append("fileDescriptor", fileDescriptor);
        container.append("pathName", pathName);
        container.append("message", message);
        container.append("status", status);
        return container;

    }

    public static Document FILE_BYTES_REQUEST(String fileMd5, long lastModified, long fileSize, String pathName, long position, long length) {
        Document container = new Document();
        container.append("command", "FILE_BYTES_REQUEST");
        Document fileDescriptor = new Document();
        fileDescriptor.append("md5", fileMd5);
        fileDescriptor.append("lastModified", lastModified);
        fileDescriptor.append("fileSize", fileSize);
        container.append("fileDescriptor", fileDescriptor);
        container.append("pathName", pathName);
        container.append("position", position);
        container.append("length", length);
        return container;
    }

    public static Document FILE_BYTES_RESPONSE(String fileMd5, long lastModified, long fileSize, String pathName, long position, long length, String content, String message, boolean status) {
        Document container = new Document();
        container.append("command", "FILE_BYTES_RESPONSE");
        Document fileDescriptor = new Document();
        fileDescriptor.append("md5", fileMd5);
        fileDescriptor.append("lastModified", lastModified);
        fileDescriptor.append("fileSize", fileSize);
        container.append("fileDescriptor", fileDescriptor);
        container.append("pathName", pathName);
        container.append("position", position);
        container.append("length", length);
        container.append("content", content);
        container.append("message", message);
        container.append("status", status);
        return container;
    }

    public static Document FILE_DELETE_RESPONSE(String fileMd5, long lastModified, long fileSize, String pathName, String message, Boolean status) {
        Document container = new Document();
        container.append("command", "FILE_DELETE_RESPONSE");
        Document fileDescriptor = new Document();
        fileDescriptor.append("md5", fileMd5);
        fileDescriptor.append("lastModified", lastModified);
        fileDescriptor.append("fileSize", fileSize);
        container.append("fileDescriptor", fileDescriptor);
        container.append("pathName", pathName);
        container.append("message", message);
        container.append("status", status);
        return container;
    }

    public static Document DIRECTORY_CREATE_RESPONSE(String pathName, String message, Boolean status) {
        Document container1 = new Document();
        container1.append("command", "DIRECTORY_CREATE_RESPONSE");
        container1.append("pathName", pathName);
        container1.append("message", message);
        container1.append("status", status);
        return container1;
    }

    public static Document FILE_MODIFY_RESPONSE(String fileMd5, long lastModified, long fileSize, String pathName, String message, Boolean status) {
        Document container = new Document();
        container.append("command", "FILE_CREATE_RESPONSE");
        Document fileDescriptor = new Document();
        fileDescriptor.append("md5", fileMd5);
        fileDescriptor.append("lastModified", lastModified);
        fileDescriptor.append("fileSize", fileSize);
        container.append("fileDescriptor", fileDescriptor);
        container.append("pathName", pathName);
        container.append("message", message);
        container.append("status", status);
        return container;
    }


    public static Document DIRECTORY_DELETE_RESPONSE(String pathName, String message, boolean status) {
        Document container1 = new Document();
        container1.append("command", "DIRECTORY_DELETE_RESPONSE");
        container1.append("pathName", pathName);
        container1.append("message", message);
        container1.append("status", status);
        return container1;
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

    /**
     * RSA public encry
     *
     * @param str       encode string
     * @param publicKey public key
     * @return secu string
     * @throws Exception process in encode exception
     */
    public static String encrypt(String str, String publicKey) throws Exception {
        //base64 public key
        byte[] decoded = Base64.getDecoder().decode(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA encode
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        String outStr = Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes("UTF-8")));
        return outStr;
    }
}
