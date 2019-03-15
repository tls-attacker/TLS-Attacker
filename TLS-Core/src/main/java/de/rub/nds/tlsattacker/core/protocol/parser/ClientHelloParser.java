/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientHelloParser extends HelloMessageParser<ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the HelloMessageParser is supposed
     *            to start parsing
     * @param array
     *            The byte[] which the HelloMessageParser is supposed to parse
     * @param version
     *            Version of the Protocol
     */
    public ClientHelloParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.CLIENT_HELLO, version);
    }

    @Override
    protected void parseHandshakeMessageContent(ClientHelloMessage msg) {
        LOGGER.debug("Parsing ClientHelloMessage");
        parseProtocolVersion(msg);
        parseRandom(msg);
        parseSessionIDLength(msg);
        parseSessionID(msg);
        if (getVersion().isDTLS()) {
            msg.setCookieLength(parseByteField(1));
            msg.setCookie(parseByteArrayField(msg.getCookieLength().getValue()));
            if (msg.getCookieLength().getValue() == 0) {
                msg.setIncludeInDigest(false);
            }
        }
        parseCipherSuiteLength(msg);
        parseCipherSuites(msg);
        parseCompressionLength(msg);
        parseCompressions(msg);
        if (hasExtensionLengthField(msg)) {
            parseExtensionLength(msg);
            if (hasExtensions(msg)) {
                parseExtensionBytes(msg);
            }
        }
    }

    @Override
    protected ClientHelloMessage createHandshakeMessage() {
        return new ClientHelloMessage();
    }

    /**
     * Reads the next bytes as the CypherSuiteLength and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCipherSuiteLength(ClientHelloMessage msg) {
        msg.setCipherSuiteLength(parseIntField(HandshakeByteLength.CIPHER_SUITES_LENGTH));
        LOGGER.debug("CipherSuiteLength: " + msg.getCipherSuiteLength().getValue());
    }

    /**
     * Reads the next bytes as the CypherSuites and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCipherSuites(ClientHelloMessage msg) {
        msg.setCipherSuites(parseByteArrayField(msg.getCipherSuiteLength().getValue()));
        LOGGER.debug("CipherSuites: " + ArrayConverter.bytesToHexString(msg.getCipherSuites().getValue()));
    }

    /**
     * Reads the next bytes as the CompressionLength and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCompressionLength(ClientHelloMessage message) {
        message.setCompressionLength(parseIntField(HandshakeByteLength.COMPRESSION_LENGTH));
        LOGGER.debug("CompressionLength: " + message.getCompressionLength().getValue());
    }

    /**
     * Reads the next bytes as the Compression and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCompressions(ClientHelloMessage message) {
        message.setCompressions(parseByteArrayField(message.getCompressionLength().getValue()));
        LOGGER.debug("Compressions: " + ArrayConverter.bytesToHexString(message.getCompressions().getValue()));
    }
}
