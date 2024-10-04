/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.serializer.packet;

import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;

public class OneRTTPacketSerializer extends QuicPacketSerializer<OneRTTPacket> {

    public OneRTTPacketSerializer(OneRTTPacket packet) {
        super(packet);
    }

    @Override
    protected byte[] serializeBytes() {
        writeProtectedFlags(packet);
        writeDestinationConnectionId(packet);
        writeProtectedPacketNumber(packet);
        writeProtectedPayload(packet);
        return getAlreadySerialized();
    }
}
