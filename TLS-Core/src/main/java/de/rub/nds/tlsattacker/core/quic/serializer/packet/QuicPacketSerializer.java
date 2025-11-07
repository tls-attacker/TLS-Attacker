/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.packet;

import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class QuicPacketSerializer<T extends QuicPacket> extends Serializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T packet;

    public QuicPacketSerializer(T packet) {
        this.packet = packet;
    }

    protected void writeProtectedFlags(T packet) {
        appendByte(packet.getProtectedFlags().getValue());
        LOGGER.debug("Protected Flags: {}", packet.getProtectedFlags().getValue());
    }

    protected void writeDestinationConnectionIdLength(T packet) {
        appendByte(packet.getDestinationConnectionIdLength().getValue());
        LOGGER.debug(
                "Destination Connection ID Length: {}",
                packet.getDestinationConnectionIdLength().getValue());
    }

    protected void writeDestinationConnectionId(T packet) {
        appendBytes(packet.getDestinationConnectionId().getValue());
        LOGGER.debug(
                "Destination Connection ID: {}", packet.getDestinationConnectionId().getValue());
    }

    protected void writeProtectedPacketNumber(T packet) {
        appendBytes(packet.getProtectedPacketNumber().getValue());
        LOGGER.debug("Protected Packet Number: {}", packet.getProtectedPacketNumber().getValue());
    }

    protected void writePacketLength(T packet) {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        packet.getPacketLength().getValue()));
        LOGGER.debug("Packet Length: {}", packet.getPacketLength().getValue());
    }

    protected void writeProtectedPayload(T packet) {
        appendBytes(packet.getProtectedPayload().getValue());
        LOGGER.debug("Protected Payload: {}", packet.getProtectedPayload().getValue());
    }
}
