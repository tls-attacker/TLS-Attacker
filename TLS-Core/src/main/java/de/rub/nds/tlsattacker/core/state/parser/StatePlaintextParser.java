/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state.parser;

import de.rub.nds.tlsattacker.core.constants.ClientAuthenticationType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.state.StatePlaintext;
import java.io.ByteArrayInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StatePlaintextParser extends Parser<StatePlaintext> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StatePlaintextParser(int startposition, byte[] array) {
        super(new ByteArrayInputStream(array, startposition, array.length - startposition));
    }

    @Override
    public void parse(StatePlaintext statePlaintext) {
        parseProtocolVersion(statePlaintext);
        parseCipherSuite(statePlaintext);
        parseCompressionMethod(statePlaintext);
        parseMasterSecret(statePlaintext);
        parseClientAuthenticationType(statePlaintext);
        if (statePlaintext.getClientAuthenticationType().getValue()
                != ClientAuthenticationType.ANONYMOUS.getValue()) {
            throw new UnsupportedOperationException(
                    "Parsing for client authentication data is not implemented yet");
        }
        parseTimestamp(statePlaintext);
    }

    private void parseProtocolVersion(StatePlaintext statePlaintext) {
        statePlaintext.setProtocolVersion(parseByteArrayField(HandshakeByteLength.VERSION));
        LOGGER.debug(
                "Parsed protocol version from state {}",
                statePlaintext.getProtocolVersion().getValue());
    }

    private void parseCipherSuite(StatePlaintext statePlaintext) {
        statePlaintext.setCipherSuite(parseByteArrayField(HandshakeByteLength.CIPHER_SUITE));
        LOGGER.debug(
                "Parsed cipher suite from state {}", statePlaintext.getCipherSuite().getValue());
    }

    private void parseCompressionMethod(StatePlaintext statePlaintext) {
        statePlaintext.setCompressionMethod(parseByteField(HandshakeByteLength.COMPRESSION));
        LOGGER.debug(
                "Parsed compression method from state "
                        + statePlaintext.getCompressionMethod().getValue());
    }

    private void parseMasterSecret(StatePlaintext statePlaintext) {
        statePlaintext.setMasterSecret(parseByteArrayField(HandshakeByteLength.MASTER_SECRET));
        LOGGER.debug(
                "Parsed master secret from state {}", statePlaintext.getMasterSecret().getValue());
    }

    private void parseClientAuthenticationType(StatePlaintext statePlaintext) {
        statePlaintext.setClientAuthenticationType(
                parseByteField(HandshakeByteLength.CLIENT_AUTHENTICATION_TYPE));
        LOGGER.debug(
                "Parsed client authentication type from state "
                        + statePlaintext.getClientAuthenticationType().getValue());
    }

    private void parseTimestamp(StatePlaintext statePlaintext) {
        statePlaintext.setTimestamp(parseIntField(HandshakeByteLength.UNIX_TIME));
        LOGGER.debug("Parsed time stamp from state " + statePlaintext.getTimestamp());
    }
}
