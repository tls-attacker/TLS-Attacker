/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.packet;

import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import de.rub.nds.tlsattacker.core.quic.packet.RetryPacket;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RetryPacketParser extends LongHeaderPacketParser<RetryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RetryPacketParser(InputStream stream, QuicContext context) {
        super(stream, context);
    }

    @Override
    public void parse(RetryPacket packet) {
        parseDestinationConnectionIdLength(packet);
        parseDestinationConnectionId(packet);
        parseSourceConnectionIdLength(packet);
        parseSourceConnectionId(packet);
        parseRetryToken(packet);
        determinePacketLength(packet);
    }

    private void determinePacketLength(RetryPacket packet) {
        // Retry Packets have no length field, but we set it nonetheless.
        packet.setPacketLength(
                23
                        + packet.getDestinationConnectionIdLength().getValue()
                        + packet.getSourceConnectionIdLength().getValue()
                        + packet.getRetryToken().getValue().length);
        packet.setPacketLengthSize(0);
    }

    private void parseRetryToken(RetryPacket packet) {
        byte[] tokenAndIntegrityTag = parseTillEnd();
        packet.setRetryToken(
                Arrays.copyOfRange(
                        tokenAndIntegrityTag,
                        0,
                        tokenAndIntegrityTag.length
                                - MiscRfcConstants.RETRY_TOKEN_INTEGRITY_TAG_LENGTH));
        LOGGER.debug("Retry Token: {}", packet.getRetryToken().getValue());
        packet.setRetryIntegrityTag(
                Arrays.copyOfRange(
                        tokenAndIntegrityTag,
                        tokenAndIntegrityTag.length
                                - MiscRfcConstants.RETRY_TOKEN_INTEGRITY_TAG_LENGTH,
                        tokenAndIntegrityTag.length));
        LOGGER.debug("Retry Integrity Tag: {}", packet.getRetryIntegrityTag().getValue());
    }
}
