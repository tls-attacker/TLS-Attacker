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

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;

/**
 *
 * @author ic0ns
 */
public abstract class TcpTransportHandler extends TransportHandler {

    public TcpTransportHandler(long timeout, ConnectionEndType type, boolean isInStreamTerminating) {
        super(timeout, type, isInStreamTerminating);
    }

    public TcpTransportHandler(long timeout, ConnectionEndType type) {
        super(timeout, type);
    }

    public abstract Integer getServerPort();

    public abstract Integer getClientPort();

    public abstract void setServerPort(int port);

    public abstract void setClientPort(int port);
}
