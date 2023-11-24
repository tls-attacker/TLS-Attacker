/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.IOException;
import java.io.InputStream;

public class OneRTTPacketParser extends QuicPacketParser<OneRTTPacket> {

    public OneRTTPacketParser(InputStream stream, QuicContext context) {
        super(stream, context);
    }

    @Override
    public void parse(OneRTTPacket packet) {
        // OneRTT Packets do not have a DCID Length Field. Therefore you need to set its Length from
        // the context
        packet.setDestinationConnectionIdLength((byte) context.getSourceConnectionId().length);
        parseDestinationConnectionId(packet);
        try {
            // packetlength must be "guessed" since short header packets do not have a length field
            // we assume that the length is equal to the length of the UDP datagram
            packet.setPacketLength(getStream().available());
            parseProtectedPacketNumberAndPayload(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}