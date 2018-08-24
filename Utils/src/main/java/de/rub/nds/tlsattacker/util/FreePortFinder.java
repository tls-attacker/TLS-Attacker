
package de.rub.nds.tlsattacker.util;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * This small Helper tries to find an empty server port. Sometimes staring a
 * server socket on port 0 is not an option
 */
public class FreePortFinder {
    /**
     * This method tries to find a FreePort. Note that there is a small
     * timeframe in which the port could be allocated by another Thread/Service
     * 
     * @return
     */
    public static int getPossiblyFreePort() {
        try {
            int port;
            try (ServerSocket socket = new ServerSocket(0)) {
                port = socket.getLocalPort();
            }
            return port;
        } catch (IOException ex) {
            throw new RuntimeException("Could not find a free Port");
        }

    }

    private FreePortFinder() {
    }
}
