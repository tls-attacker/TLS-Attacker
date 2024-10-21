/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketByteLength;
import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionNegotiationPacketParser
        extends LongHeaderPacketParser<VersionNegotiationPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionNegotiationPacketParser(InputStream stream, QuicContext context) {
        super(stream, context);
    }

    @Override
    public void parse(VersionNegotiationPacket packet) {
        parseDestinationConnectionIdLength(packet);
        parseDestinationConnectionId(packet);
        parseSourceConnectionIdLength(packet);
        parseSourceConnectionId(packet);
        parseSupportedVersion(packet);
    }

    protected void parseSupportedVersion(VersionNegotiationPacket packet) {
        try {
            while (getStream().available() > 0) {
                packet.setSupportedVersions(
                        parseByteArrayField(QuicPacketByteLength.QUIC_VERSION_LENGTH));
            }
        } catch (EndOfStreamException | ParserException | TimeoutException | IOException e) {
            LOGGER.error("No more versions to parse in Version Negotiation Packet");
        }
        LOGGER.debug("Supported Versions: {}", packet.getSupportedVersions().getValue());
    }
}
