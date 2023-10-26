/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.InputStream;

public class HandshakePacketParser extends LongHeaderPacketParser<HandshakePacket> {

    public HandshakePacketParser(InputStream stream, QuicContext context) {
        super(stream, context);
    }

    @Override
    public void parse(HandshakePacket packet) {
        parseDestinationConnectionIdLength(packet);
        parseDestinationConnectionId(packet);
        parseSourceConnectionIdLength(packet);
        parseSourceConnectionId(packet);
        parsePacketLength(packet);
        parseProtectedPacketNumberAndPayload(packet);
    }
}
