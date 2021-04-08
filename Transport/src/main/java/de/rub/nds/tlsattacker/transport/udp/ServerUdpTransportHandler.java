/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.udp;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpInputStream;
import de.rub.nds.tlsattacker.transport.udp.stream.UdpOutputStream;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.DatagramSocket;

public class ServerUdpTransportHandler extends UdpTransportHandler {

    public ServerUdpTransportHandler(Connection con) {
        super(con);
        this.port = con.getPort();
    }

    public ServerUdpTransportHandler(long firstTimeout, long timeout, int port) {
        super(firstTimeout, timeout, ConnectionEndType.SERVER);
        this.port = port;
    }

    @Override
    public void initialize() throws IOException {
        socket = new DatagramSocket(port);
        setStreams(new PushbackInputStream(new UdpInputStream(socket, true)), new UdpOutputStream(socket));
        srcPort = socket.getLocalPort();
        dstPort = socket.getPort();
        cachedSocketState = null;
        // this could be made an option
        waitOnReceive();
    }

    /*
     * Provides a routine equivalent to TCP's accept method. Blocks until a client "connects", meaning that data is
     * available to be read.
     */
    private void waitOnReceive() throws IOException {
        while (inStream.available() == 0) {
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
            }
        }
    }

    public int getPort() {
        return port;
    }
}
