/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.Connection;

import java.io.IOException;

public class ClientTcpNoDelayTransportHandler extends ClientTcpTransportHandler {

    public ClientTcpNoDelayTransportHandler(Connection con) {
        super(con);
    }

    public ClientTcpNoDelayTransportHandler(long firstTimeout, long timeout, String hostname, int port) {
        super(firstTimeout, timeout, hostname, port);
    }

    @Override
    public void initialize() throws IOException {
        super.initialize();
        socket.setTcpNoDelay(true);
        cachedSocketState = null;
    }
}
