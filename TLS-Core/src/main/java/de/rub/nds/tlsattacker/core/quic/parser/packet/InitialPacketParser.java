/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class InitialPacketParser extends LongHeaderPacketParser<InitialPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public InitialPacketParser(InputStream stream, QuicContext context) {
        super(stream, context);
    }

    @Override
    public void parse(InitialPacket packet) {
        parseDestinationConnectionIdLength(packet);
        parseDestinationConnectionId(packet);
        parseSourceConnectionIdLength(packet);
        parseSourceConnectionId(packet);
        parseTokenLength(packet);
        parseToken(packet);
        parsePacketLength(packet);
        parseProtectedPacketNumberAndPayload(packet);
        context.setDestinationConnectionId(packet.getSourceConnectionId().getValue());
    }

    protected void parseTokenLength(InitialPacket message) {
        try {
            int before = getStream().available();
            int result = (int) parseVariableLengthInteger();
            int after = getStream().available();
            message.setTokenLength(result);
            message.setTokenLengthSize(before - after);
            message.protectedHeaderHelper.write(quicBuffer.toByteArray());
            quicBuffer.reset();
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    protected void parseToken(InitialPacket message) {
        byte[] tokenBytes = parseByteArrayField(message.getTokenLength().getValue());
        message.setToken(tokenBytes);
        try {
            message.protectedHeaderHelper.write(tokenBytes);
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }
}
