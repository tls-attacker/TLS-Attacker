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
import de.rub.nds.tlsattacker.core.quic.VariableLengthIntegerEncoding;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;

public abstract class QuicPacketSerializer<T extends QuicPacket> extends Serializer<T> {

    protected final T packet;

    public QuicPacketSerializer(T packet) {
        this.packet = packet;
    }

    protected void writeProtectedFlags(T packet) {
        appendByte(packet.getProtectedFlags().getValue());
    }

    protected void writeDestinationConnectionIdLength(T packet) {
        appendByte(packet.getDestinationConnectionIdLength().getValue());
    }

    protected void writeDestinationConnectionId(T packet) {
        appendBytes(packet.getDestinationConnectionId().getValue());
    }

    protected void writeProtectedPacketNumber(T packet) {
        appendBytes(packet.getProtectedPacketNumber().getValue());
    }

    protected void writePacketLength(T packet) {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        packet.getPacketLength().getValue()));
    }

    protected void writeProtectedPayload(T packet) {
        appendBytes(packet.getProtectedPayload().getValue());
    }
}
