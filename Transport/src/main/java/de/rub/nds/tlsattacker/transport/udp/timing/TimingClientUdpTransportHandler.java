/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.udp.timing;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TimeableTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ClientUdpTransportHandler;
import java.net.NetworkInterface;

public class TimingClientUdpTransportHandler extends ClientUdpTransportHandler
        implements TimeableTransportHandler {

    public TimingClientUdpTransportHandler(Connection connection) {
        super(connection);
    }

    public TimingClientUdpTransportHandler(
            long firstTimeout,
            long timeout,
            String hostname,
            int port,
            NetworkInterface networkInterface) {
        super(firstTimeout, timeout, hostname, port, networkInterface);
    }

    public TimingClientUdpTransportHandler(
            long firstTimeout, long timeout, String hostname, int port) {
        super(firstTimeout, timeout, hostname, port);
    }

    @Override
    public Long getLastMeasurement() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
