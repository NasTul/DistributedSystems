package unimelb.bitbox;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class test {

    public static void main( String[] args ) throws UnknownHostException {

        InetAddress inetAddress = InetAddress.getLocalHost();
        System.out.println("ip="+inetAddress.getHostAddress());

    }
}
