/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.context.MessageParserBoundaryVerificationContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientHelloParser extends HelloMessageParser<ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *                Position in the array where the HelloMessageParser is supposed to start parsing
     * @param array
     *                The byte[] which the HelloMessageParser is supposed to parse
     * @param version
     *                Version of the Protocol
     * @param config
     *                A Config used in the current context
     */
    public ClientHelloParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, HandshakeMessageType.CLIENT_HELLO, version, config);
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
        }
        parseCipherSuiteLength(msg);
        parseCipherSuites(msg);
        parseCompressionLength(msg);
        parseCompressions(msg);
        if (hasExtensionLengthField(msg)) {
            parseExtensionLength(msg);
            if (hasExtensions(msg)) {
                pushContext(new MessageParserBoundaryVerificationContext(msg.getExtensionsLength().getValue(),
                    "Extension Length", getPointer(), getConfig().isThrowExceptionOnParserContextViolation()));
                parseExtensionBytes(msg);
                popContext();

            }
        }
    }

    @Override
    protected ClientHelloMessage createHandshakeMessage() {
        return new ClientHelloMessage();
    }

    /**
     * Reads the next bytes as the CypherSuiteLength and writes them in the message
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
     * Reads the next bytes as the CompressionLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCompressionLength(ClientHelloMessage msg) {
        msg.setCompressionLength(parseIntField(HandshakeByteLength.COMPRESSION_LENGTH));
        LOGGER.debug("CompressionLength: " + msg.getCompressionLength().getValue());
    }

    /**
     * Reads the next bytes as the Compression and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCompressions(ClientHelloMessage msg) {
        msg.setCompressions(parseByteArrayField(msg.getCompressionLength().getValue()));
        LOGGER.debug("Compressions: " + ArrayConverter.bytesToHexString(msg.getCompressions().getValue()));
    }
}
