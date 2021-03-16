/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.nonblocking;

import java.io.IOException;
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
                socket.connect(new InetSocketAddress(host, port));
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
