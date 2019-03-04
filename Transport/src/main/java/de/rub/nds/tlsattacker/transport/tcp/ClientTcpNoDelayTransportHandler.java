/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.Socket;

public class ClientTcpNoDelayTransportHandler extends ClientTcpTransportHandler {

    public ClientTcpNoDelayTransportHandler(long timeout, String hostname, int port) {
        super(timeout, hostname, port);
    }

    @Override
    public void initialize() throws IOException {
        socket = new Socket(hostname, port);
        socket.setTcpNoDelay(true);
        setStreams(new PushbackInputStream(socket.getInputStream()), socket.getOutputStream());
    }
}
