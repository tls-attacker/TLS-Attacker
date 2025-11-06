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
    }

    protected void parseTokenLength(InitialPacket packet) {
        try {
            int before = getStream().available();
            int result = (int) parseVariableLengthInteger();
            int after = getStream().available();
            packet.setTokenLength(result);
            packet.setTokenLengthSize(before - after);
            packet.protectedHeaderHelper.write(quicBuffer.toByteArray());
            quicBuffer.reset();
        } catch (IOException e) {
            LOGGER.error(e);
        }
        LOGGER.debug("Token Length: {}", packet.getTokenLength().getValue());
    }

    protected void parseToken(InitialPacket packet) {
        byte[] tokenBytes = parseByteArrayField(packet.getTokenLength().getValue());
        packet.setToken(tokenBytes);
        packet.protectedHeaderHelper.write(tokenBytes);
        LOGGER.debug("Token: {}", packet.getToken().getValue());
    }
}
