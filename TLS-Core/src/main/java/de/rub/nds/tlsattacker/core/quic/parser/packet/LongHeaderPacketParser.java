/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketByteLength;
import de.rub.nds.tlsattacker.core.quic.packet.LongHeaderPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class LongHeaderPacketParser<T extends LongHeaderPacket>
        extends QuicPacketParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public LongHeaderPacketParser(InputStream stream, QuicContext context) {
        super(stream, context);
    }

    protected void parseSourceConnectionIdLength(T packet) {
        byte idLengthBytes = parseByteField(QuicPacketByteLength.SOURCE_CONNECTION_ID_LENGTH);
        packet.setSourceConnectionIdLength(idLengthBytes);
        packet.protectedHeaderHelper.write(idLengthBytes);
        LOGGER.debug(
                "Source Connection ID Length: {}", packet.getSourceConnectionIdLength().getValue());
    }

    protected void parseSourceConnectionId(T packet) {
        byte[] sourceIdBytes =
                parseByteArrayField(packet.getSourceConnectionIdLength().getValue() & 0xFF);
        packet.setSourceConnectionId(sourceIdBytes);
        try {
            packet.protectedHeaderHelper.write(sourceIdBytes);
        } catch (IOException e) {
            LOGGER.error(e);
        }
        LOGGER.debug("Source Connection ID: {}", packet.getSourceConnectionId().getValue());
    }
}
