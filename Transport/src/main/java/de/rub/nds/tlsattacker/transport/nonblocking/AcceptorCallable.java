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
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AcceptorCallable implements Callable<Socket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerSocket serverSocket;

    private Socket clientConnection = null;

    public AcceptorCallable(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
    }

    @Override
    public Socket call() throws Exception {
        try {
            clientConnection = serverSocket.accept();
            return clientConnection;
        } catch (IOException ex) {
            LOGGER.warn("Could not open Accept connection!", ex);
        }
        return null;
    }
}
