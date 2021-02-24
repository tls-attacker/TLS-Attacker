/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.transport.nonblocking;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SocketOpenerCallable implements Callable<Socket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String host;
    private final int port;

    public SocketOpenerCallable(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @Override
    public Socket call() throws Exception {
        while (true) {
            Socket socket = new Socket();
            try {
                socket.connect(new InetSocketAddress(host, port), 10000);
                if (socket.isConnected()) {
                    return socket;
                }
            } catch (IOException e) {
                LOGGER.debug(e);
                return null;
            }
        }
    }

}
