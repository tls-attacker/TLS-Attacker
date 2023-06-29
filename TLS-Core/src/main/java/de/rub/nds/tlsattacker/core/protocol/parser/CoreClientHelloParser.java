/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class CoreClientHelloParser<T extends CoreClientHelloMessage>
        extends HelloMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream InputStream that contains data to parse
     * @param tlsContext Context of this connection
     */
    public CoreClientHelloParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(T msg) {
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
     * @param msg Message to write in
     */
    private void parseCipherSuiteLength(T msg) {
        msg.setCipherSuiteLength(parseIntField(HandshakeByteLength.CIPHER_SUITES_LENGTH));
        LOGGER.debug("CipherSuiteLength: " + msg.getCipherSuiteLength().getValue());
    }

    /**
     * Reads the next bytes as the CypherSuites and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseCipherSuites(T msg) {
        msg.setCipherSuites(parseByteArrayField(msg.getCipherSuiteLength().getValue()));
        LOGGER.debug(
                "CipherSuites: "
                        + ArrayConverter.bytesToHexString(msg.getCipherSuites().getValue()));
    }

    /**
     * Reads the next bytes as the CompressionLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseCompressionLength(T msg) {
        msg.setCompressionLength(parseIntField(HandshakeByteLength.COMPRESSION_LENGTH));
        LOGGER.debug("CompressionLength: " + msg.getCompressionLength().getValue());
    }

    /**
     * Reads the next bytes as the Compression and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseCompressions(T msg) {
        msg.setCompressions(parseByteArrayField(msg.getCompressionLength().getValue()));
        LOGGER.debug(
                "Compressions: "
                        + ArrayConverter.bytesToHexString(msg.getCompressions().getValue()));
    }
}
