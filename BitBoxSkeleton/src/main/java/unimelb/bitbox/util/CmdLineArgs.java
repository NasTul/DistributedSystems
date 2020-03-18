package unimelb.bitbox.util;

//Remember to add the args4j jar to your project's build path

import org.kohsuke.args4j.Option;

//This class is where the arguments read from the command line will be stored
//Declare one field for each argument and use the @Option annotation to link the field
//to the argument name, args4J will parse the arguments and based on the name,
//it will automatically update the field with the parsed argument value
public class CmdLineArgs {

    @Option(required = true, name = "-s", usage = "server host")
    private String serverHost;

    @Option(required = false, name = "-p", usage = "peer host")
    private String peerHost;

    @Option(required = true, name = "-c", usage = "Port number")
    private String function;

    @Option(required = true, name = "-i", usage = "identity")
    private String identity;

    public String getServerHost() {
        return serverHost;
    }

    public String getPeerHost() {
        return peerHost;
    }

    public String getfunction() {
        return function;
    }

    public String getIdentity() {
        return identity;
    }
}

