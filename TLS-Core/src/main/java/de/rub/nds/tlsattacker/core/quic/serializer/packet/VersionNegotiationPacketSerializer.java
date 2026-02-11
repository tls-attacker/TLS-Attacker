/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.packet;

import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionNegotiationPacketSerializer
        extends LongHeaderPacketSerializer<VersionNegotiationPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionNegotiationPacketSerializer(VersionNegotiationPacket packet) {
        super(packet);
    }

    @Override
    protected byte[] serializeBytes() {
        writeUnprotectedFlags(packet);
        appendBytes(new byte[] {0x00, 0x00, 0x00, 0x00});
        writeDestinationConnectionIdLength(packet);
        writeDestinationConnectionId(packet);
        writeSourceConnectionIdLength(packet);
        writeSourceConnectionId(packet);
        appendBytes(QuicVersion.VERSION_1.getByteValue());
        return getAlreadySerialized();
    }

    protected void writeUnprotectedFlags(VersionNegotiationPacket packet) {
        appendByte(packet.getUnprotectedFlags().getValue());
        LOGGER.debug("Unprotected Flags: {}", packet.getUnprotectedFlags().getValue());
    }
}
