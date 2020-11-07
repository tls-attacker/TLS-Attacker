/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.transport.udp.timing;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TimeableTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ClientUdpTransportHandler;

public class TimingClientUdpTransportHandler extends ClientUdpTransportHandler implements TimeableTransportHandler {

    public TimingClientUdpTransportHandler(Connection connection) {
        super(connection);
    }

    public TimingClientUdpTransportHandler(long timeout, String hostname, int port) {
        super(timeout, hostname, port);
    }

    @Override
    public Long getLastMeasurement() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
