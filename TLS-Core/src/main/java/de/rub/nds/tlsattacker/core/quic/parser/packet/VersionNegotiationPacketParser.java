/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
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

        packet.setUnprotectedPayload(new byte[0]);
    }

    protected void parseSupportedVersion(VersionNegotiationPacket packet) {
        packet.setSupportedVersions(parseTillEnd());
        LOGGER.debug("Supported Versions: {}", packet.getSupportedVersions().getValue());
    }
}
