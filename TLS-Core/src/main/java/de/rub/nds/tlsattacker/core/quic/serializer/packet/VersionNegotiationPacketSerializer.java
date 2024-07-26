/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.packet;

import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;

public class VersionNegotiationPacketSerializer
        extends LongHeaderPacketSerializer<VersionNegotiationPacket> {

    public VersionNegotiationPacketSerializer(VersionNegotiationPacket packet) {
        super(packet);
    }

    @Override
    protected byte[] serializeBytes() {
        // TODO
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
