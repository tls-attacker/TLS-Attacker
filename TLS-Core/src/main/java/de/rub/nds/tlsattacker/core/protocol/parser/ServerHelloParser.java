/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Parser class for ServerHelloMessages */
public class ServerHelloParser extends HelloMessageParser<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the ServerHelloMessageParser
     *
     * @param stream
     * @param tlsContext The current context
     */
    public ServerHelloParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    /**
     * Reads the next bytes as a CipherSuite and writes them in the message
     *
     * @param msg Message to write in
     */
    protected void parseSelectedCipherSuite(ServerHelloMessage msg) {
        msg.setSelectedCipherSuite(parseByteArrayField(HandshakeByteLength.CIPHER_SUITE));
    }

    /**
     * Reads the next bytes as a CompressionMethod and writes them in the message
     *
     * @param msg Message to write in
     */
    protected void parseSelectedCompressionMethod(ServerHelloMessage msg) {
        msg.setSelectedCompressionMethod(parseByteField(HandshakeByteLength.COMPRESSION));
    }

    @Override
    public void parse(ServerHelloMessage msg) {
        LOGGER.debug("Parsing ServerHelloMessage");
        parseProtocolVersion(msg);
        ProtocolVersion version =
                ProtocolVersion.getProtocolVersion(msg.getProtocolVersion().getValue());
        if (version != null) {
            setVersion(version);
        }
        parseRandom(msg);
        parseSessionIDLength(msg);
        parseSessionID(msg);
        parseSelectedCipherSuite(msg);
        parseSelectedCompressionMethod(msg);

        LOGGER.trace("Checking for ExtensionLength Field");
        if (hasExtensionLengthField()) {
            LOGGER.trace("Parsing ExtensionLength field");
            parseExtensionLength(msg);
            parseExtensionBytes(msg, msg.isTls13HelloRetryRequest());
        }
    }
}
