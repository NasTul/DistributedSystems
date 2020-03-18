package unimelb.bitbox.util;

import java.io.PrintStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

public class ClientHandle extends Thread {
    private static Logger log = Logger.getLogger(ClientHandle.class.getName());
    private LinkedBlockingQueue<Document> requestQueue = null;
    ArrayList<Socket> clients = null;
    PeersPool peersPool = null;

    public ClientHandle(ArrayList<Socket> clients, LinkedBlockingQueue<Document> requestQueue, PeersPool peersPool) {
        this.clients = clients;
        this.requestQueue = requestQueue;
        this.peersPool = peersPool;
        start();

    }

    public void run() {

        try {
            while (true) {
                Document request = requestQueue.take();
                String strLine = "";
                String command = request.getString("command");
                if (command == null) {
                    continue;
                }
                for (Socket client : clients) {
                    try {
                        PrintStream out = new PrintStream(client.getOutputStream());
                        strLine = request.toJson();
                        //strLine = Base64.getEncoder().encodeToString(strLine.getBytes());
                        out.println(strLine);
                    } catch (Exception e) {

                    }
                }
                for (Socket client : peersPool.clients) {
                    try {
                        PrintStream out = new PrintStream(client.getOutputStream());
                        strLine = request.toJson();
                        // strLine = Base64.getEncoder().encodeToString(strLine.getBytes());
                        out.println(strLine);
                    } catch (Exception e) {

                    }
                }
            }
        } catch (Exception e) {

        }

    }


}
