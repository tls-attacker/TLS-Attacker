package de.rub.nds.tlsattacker.randomtester;

import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class Main {

    private static int REQUESTS = 200;

    public static void main(String[] args) {
	int requests = REQUESTS;
	if (args.length > 0) {
	    requests = Integer.parseInt(args[0]);
	}
	ClientCommandConfig ccc = new ClientCommandConfig();
	ccc.setConnect("localhost:8443");
	RandomClient rc = new RandomClient(ccc, requests);
	RandomClient.initializeRequest();

	rc.sendRequests();
    }
}
