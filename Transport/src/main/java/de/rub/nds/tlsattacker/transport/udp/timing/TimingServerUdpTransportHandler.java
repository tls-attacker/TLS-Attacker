/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.transport.udp.timing;

import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TimeableTransportHandler;
import de.rub.nds.tlsattacker.transport.udp.ServerUdpTransportHandler;

public class TimingServerUdpTransportHandler extends ServerUdpTransportHandler
        implements TimeableTransportHandler {

    public TimingServerUdpTransportHandler(Connection con) {
        super(con);
    }

    public TimingServerUdpTransportHandler(long firstTimeout, long timeout, int port) {
        super(firstTimeout, timeout, port);
    }

    @Override
    public Long getLastMeasurement() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
