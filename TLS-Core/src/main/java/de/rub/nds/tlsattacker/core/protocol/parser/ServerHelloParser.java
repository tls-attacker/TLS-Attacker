/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parser class for ServerHelloMessages
 */
public class ServerHelloParser extends HelloMessageParser<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConnectionEndType talkingConnectionEndType;

    /**
     * Constructor for the ServerHelloMessageParser
     *
     * @param stream
     * @param version
     *                   The Version for which this message should be parsed
     * @param tlsContext
     *                   A Config used in the current context
     */
    public ServerHelloParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext,
        ConnectionEndType talkingConnectionEndType) {
        super(stream, HandshakeMessageType.SERVER_HELLO, version, tlsContext);
        this.talkingConnectionEndType = talkingConnectionEndType;
    }

    /**
     * Reads the next bytes as a CipherSuite and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    protected void parseSelectedCipherSuite(ServerHelloMessage msg) {
        msg.setSelectedCipherSuite(parseByteArrayField(HandshakeByteLength.CIPHER_SUITE));
    }

    /**
     * Reads the next bytes as a CompressionMethod and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    protected void parseSelectedCompressionMethod(ServerHelloMessage msg) {
        msg.setSelectedCompressionMethod(parseByteField(HandshakeByteLength.COMPRESSION));
    }

    @Override
    protected void parseHandshakeMessageContent(ServerHelloMessage msg) {
        LOGGER.debug("Parsing ServerHelloMessage");
        parseProtocolVersion(msg);
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(msg.getProtocolVersion().getValue());
        if (version != null) {
            setVersion(version);
        }
        parseRandom(msg);
        parseSessionIDLength(msg);
        parseSessionID(msg);
        parseSelectedCipherSuite(msg);
        parseSelectedCompressionMethod(msg);

        LOGGER.trace("Checking for ExtensionLength Field");
        if (hasExtensionLengthField(msg)) {
            LOGGER.trace("Parsing ExtensionLength field");
            parseExtensionLength(msg);
            parseExtensionBytes(msg, getVersion(), talkingConnectionEndType, msg.isTls13HelloRetryRequest());
        }
    }
}
