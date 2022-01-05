/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.state.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ClientAuthenticationType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.state.StatePlaintext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StatePlaintextParser extends Parser<StatePlaintext> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StatePlaintextParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public StatePlaintext parse() {
        StatePlaintext statePlaintext = new StatePlaintext();
        parseProtocolVersion(statePlaintext);
        parseCipherSuite(statePlaintext);
        parseCompressionMethod(statePlaintext);
        parseMasterSecret(statePlaintext);
        parseClientAuthenticationType(statePlaintext);
        if (statePlaintext.getClientAuthenticationType().getValue() != ClientAuthenticationType.ANONYMOUS.getValue()) {
            throw new UnsupportedOperationException("Parsing for client authentication data is not implemented yet");
        }
        parseTimestamp(statePlaintext);
        return statePlaintext;
    }

    private void parseProtocolVersion(StatePlaintext statePlaintext) {
        statePlaintext.setProtocolVersion(parseByteArrayField(HandshakeByteLength.VERSION));
        LOGGER.debug("Parsed protocol version from state "
            + ArrayConverter.bytesToHexString(statePlaintext.getProtocolVersion().getValue()));
    }

    private void parseCipherSuite(StatePlaintext statePlaintext) {
        statePlaintext.setCipherSuite(parseByteArrayField(HandshakeByteLength.CIPHER_SUITE));
        LOGGER.debug("Parsed cipher suite from state "
            + ArrayConverter.bytesToHexString(statePlaintext.getCipherSuite().getValue()));
    }

    private void parseCompressionMethod(StatePlaintext statePlaintext) {
        statePlaintext.setCompressionMethod(parseByteField(HandshakeByteLength.COMPRESSION));
        LOGGER.debug("Parsed compression method from state " + statePlaintext.getCompressionMethod().getValue());
    }

    private void parseMasterSecret(StatePlaintext statePlaintext) {
        statePlaintext.setMasterSecret(parseByteArrayField(HandshakeByteLength.MASTER_SECRET));
        LOGGER.debug("Parsed master secret from state "
            + ArrayConverter.bytesToHexString(statePlaintext.getMasterSecret().getValue()));
    }

    private void parseClientAuthenticationType(StatePlaintext statePlaintext) {
        statePlaintext.setClientAuthenticationType(parseByteField(HandshakeByteLength.CLIENT_AUTHENTICATION_TYPE));
        LOGGER.debug(
            "Parsed client authentication type from state " + statePlaintext.getClientAuthenticationType().getValue());
    }

    private void parseTimestamp(StatePlaintext statePlaintext) {
        statePlaintext.setTimestamp(parseIntField(HandshakeByteLength.UNIX_TIME));
        LOGGER.debug("Parsed time stamp from state " + statePlaintext.getTimestamp());
    }

}
