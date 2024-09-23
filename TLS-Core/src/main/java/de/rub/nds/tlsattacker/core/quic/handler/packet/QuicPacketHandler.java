/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.handler.packet;

import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicPacketHandler<T extends QuicPacket> extends Handler<T> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final QuicContext quicContext;

    public QuicPacketHandler(QuicContext quicContext) {
        this.quicContext = quicContext;
    }
}
