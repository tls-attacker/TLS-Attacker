/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parser class for ServerHelloMessages
 */
public class ServerHelloParser extends HelloMessageParser<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the ServerHelloMessageParser
     *
     * @param pointer
     *            Position in the array where the ServerHellorParser is supposed
     *            to start parsing
     * @param array
     *            The byte[] which the ServerHellorParser is supposed to parse
     * @param version
     *            The Version for which this message should be parsed
     */
    public ServerHelloParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SERVER_HELLO, version);
    }

    /**
     * Reads the next bytes as a CipherSuite and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    protected void parseSelectedCiphersuite(ServerHelloMessage msg) {
        msg.setSelectedCipherSuite(parseByteArrayField(HandshakeByteLength.CIPHER_SUITE));
    }

    /**
     * Reads the next bytes as a CompressionMethod and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    protected void parseSelectedComressionMethod(ServerHelloMessage msg) {
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
        if (!getVersion().isTLS13()) {
            parseSessionIDLength(msg);
            parseSessionID(msg);
        }
        parseSelectedCiphersuite(msg);
        if (!getVersion().isTLS13()) {
            parseSelectedComressionMethod(msg);
        }
        LOGGER.trace("Checking for ExtensionLengthField");
        if (hasExtensionLengthField(msg)) {
            LOGGER.trace("Parsing ExtensionLength field");
            parseExtensionLength(msg);
            parseExtensionBytes(msg);
        }
    }

    @Override
    protected ServerHelloMessage createHandshakeMessage() {
        return new ServerHelloMessage();
    }
}
