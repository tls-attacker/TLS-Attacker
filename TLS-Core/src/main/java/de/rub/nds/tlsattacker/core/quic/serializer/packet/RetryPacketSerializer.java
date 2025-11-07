/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.packet;

import de.rub.nds.tlsattacker.core.quic.packet.RetryPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RetryPacketSerializer extends LongHeaderPacketSerializer<RetryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RetryPacketSerializer(RetryPacket packet) {
        super(packet);
    }

    @Override
    protected byte[] serializeBytes() {
        writeUnprotectedFlags(packet);
        writeQuicVersion(packet);
        writeDestinationConnectionIdLength(packet);
        writeDestinationConnectionId(packet);
        writeSourceConnectionIdLength(packet);
        writeSourceConnectionId(packet);
        writeRetryToken(packet);
        writeRetryIntegrityTag(packet);
        return getAlreadySerialized();
    }

    protected void writeUnprotectedFlags(RetryPacket packet) {
        appendByte(packet.getUnprotectedFlags().getValue());
        LOGGER.debug("Unprotected Flags: {}", packet.getUnprotectedFlags().getValue());
    }

    protected void writeRetryToken(RetryPacket packet) {
        if (packet.getRetryToken() != null) {
            appendBytes(packet.getRetryToken().getValue());
            LOGGER.debug("Retry Token: {}", packet.getRetryToken().getValue());
        }
    }

    protected void writeRetryIntegrityTag(RetryPacket packet) {
        if (packet.getRetryIntegrityTag() != null) {
            appendBytes(packet.getRetryIntegrityTag().getValue());
            LOGGER.debug("Retry Integrity Tag: {}", packet.getRetryIntegrityTag().getValue());
        }
    }
}
