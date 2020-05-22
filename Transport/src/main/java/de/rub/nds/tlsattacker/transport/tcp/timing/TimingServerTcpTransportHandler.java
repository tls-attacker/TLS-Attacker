/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.transport.tcp.timing;

import de.rub.nds.tlsattacker.transport.TimeableTransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;

public class TimingServerTcpTransportHandler extends ServerTcpTransportHandler implements TimeableTransportHandler {

    public TimingServerTcpTransportHandler(long firstTimeout, long timeout, int port) {
        super(firstTimeout, timeout, port);
    }

    @Override
    public Long getLastMeasurement() {
        throw new UnsupportedOperationException("Not supported yet."); // To
        // change
        // body
        // of
        // generated
        // methods,
        // choose
        // Tools
        // |
        // Templates.
    }
}
