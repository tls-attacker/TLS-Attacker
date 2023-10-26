/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.packet;

import de.rub.nds.tlsattacker.core.quic.VariableLengthIntegerEncoding;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;

public class InitialPacketSerializer extends LongHeaderPacketSerializer<InitialPacket> {

    public InitialPacketSerializer(InitialPacket packet) {
        super(packet);
    }

    @Override
    protected byte[] serializeBytes() {
        writeProtectedFlags(packet);
        writeQuicVersion(packet);
        writeDestinationConnectionIdLength(packet);
        writeDestinationConnectionId(packet);
        writeSourceConnectionIdLength(packet);
        writeSourceConnectionId(packet);
        writeTokenLength(packet);
        writeToken(packet);
        writePacketLength(packet);
        writeProtectedPacketNumber(packet);
        writeProtectedPayload(packet);
        return getAlreadySerialized();
    }

    protected void writeTokenLength(InitialPacket packet) {
        appendBytes(
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                        packet.getTokenLength().getValue()));
    }

    protected void writeToken(InitialPacket packet) {
        if (packet.getToken() != null) {
            appendBytes(packet.getToken().getValue());
        }
    }
}
