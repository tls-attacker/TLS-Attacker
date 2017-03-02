/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parser class for ServerHelloMessages
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerHelloParser extends HelloParser<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger(ServerHelloParser.class);

    /**
     * Constructor for the ServerHelloMessageParser
     *
     * @param pointer
     *            Position in the array where the ServerHellorParser is supposed
     *            to start parsing
     * @param array
     *            The byte[] which the ServerHellorParser is supposed to parse
     */
    public ServerHelloParser(int pointer, byte[] array) {
        super(pointer, array, HandshakeMessageType.SERVER_HELLO);
    }

    /**
     * Reads the next bytes as a CipherSuite and writes them in the message
     *
     * @param message
     *            Message to write in
     */
    protected void parseSelectedCiphersuite(ServerHelloMessage message) {
        message.setSelectedCipherSuite(parseByteArrayField(HandshakeByteLength.CIPHER_SUITE));
    }

    /**
     * Reads the next bytes as a CompressionMethod and writes them in the
     * message
     *
     * @param message
     *            Message to write in
     */
    protected void parseSelectedComressionMethod(ServerHelloMessage message) {
        message.setSelectedCompressionMethod(parseByteField(HandshakeByteLength.COMPRESSION));
    }

    @Override
    protected void parseHandshakeMessageContent(ServerHelloMessage msg) {
        parseProtocolVersion(msg);
        parseUnixtime(msg);
        parseRandom(msg);
        parseSessionIDLength(msg);
        parseSessionID(msg);
        parseSelectedCiphersuite(msg);
        parseSelectedComressionMethod(msg);
        if (hasExtensionLengthField(msg)) {
            parseExtensionLength(msg);
            if (hasExtensions(msg)) {
                parseExtensionBytes(msg);
            }
        }
    }

    @Override
    protected ServerHelloMessage createHandshakeMessage() {
        return new ServerHelloMessage();
    }
}
