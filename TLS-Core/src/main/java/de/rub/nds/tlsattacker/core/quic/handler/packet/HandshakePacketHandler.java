/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.handler.packet;

import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;

public class HandshakePacketHandler extends LongHeaderPacketHandler<HandshakePacket> {

    public HandshakePacketHandler(QuicContext quicContext) {
        super(quicContext);
    }

    @Override
    public void adjustContext(HandshakePacket object) {}
}
