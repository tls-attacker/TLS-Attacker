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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientHelloParser extends HelloMessageParser<ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public ClientHelloParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(ClientHelloMessage msg) {
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
        if (hasExtensionLengthField()) {
            parseExtensionLength(msg);
            if (hasExtensions(msg)) {
                parseExtensionBytes(msg, false);

            }
        }
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
