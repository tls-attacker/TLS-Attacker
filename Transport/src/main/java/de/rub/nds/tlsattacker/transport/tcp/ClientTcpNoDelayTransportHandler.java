/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp;

import de.rub.nds.tlsattacker.transport.Connection;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.ConnectException;
import java.net.Socket;

public class ClientTcpNoDelayTransportHandler extends ClientTcpTransportHandler {

    public ClientTcpNoDelayTransportHandler(Connection con) {
        super(con);
    }

    public ClientTcpNoDelayTransportHandler(long firstTimeout, long timeout, String hostname, int port) {
        super(firstTimeout, timeout, hostname, port);
    }

    @Override
    public void initialize() throws IOException {
        long connectTimeout = System.currentTimeMillis() + this.connectionTimeout;
        while (System.currentTimeMillis() < connectTimeout || this.connectionTimeout == 0) {
            try {
                socket = new Socket(hostname, port);
                socket.setTcpNoDelay(true);
                srcPort = socket.getLocalPort();
                dstPort = socket.getPort();
                setStreams(new PushbackInputStream(socket.getInputStream()), socket.getOutputStream());
                break;
            } catch (ConnectException E) {
                try {
                    Thread.sleep(500);
                } catch (Exception ignore) {

                }
            }
        }
    }
}
