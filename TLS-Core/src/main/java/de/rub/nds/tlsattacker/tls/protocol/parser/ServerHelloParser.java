/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
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
     * Constructor for the ServerHellorParser
     *
     * @param pointer Position in the array where the ServerHellorParser is
     * supposed to start parsing
     * @param array The byte[] which the ServerHellorParser is supposed to parse
     */
    public ServerHelloParser(int pointer, byte[] array) {
        super(pointer, array);
    }

    /**
     * Parses the byte[] specified in the Constructor into a ServerHelloMessage
     * starting from the provided start position.
     *
     * @return
     */
    @Override
    public ServerHelloMessage parse() {
        ServerHelloMessage message = new ServerHelloMessage();
        parseType(message);
        parseLength(message);
        parseProtocolVersion(message);
        parseUnixtime(message);
        parseRandom(message);
        parseSessionIDLength(message);
        parseSessionID(message);
        parseSelectedCiphersuite(message);
        parseSelectedComressionMethod(message);
        if (hasExtensionLengthField(message)) {
            parseExtensionLength(message);
            if (hasExtensions(message)) {
                parseExtensionBytes(message);
            }
        }
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

    /**
     * Reads the next bytes as a CipherSuite and writes them in the message
     *
     * @param message Message to write in
     */
    protected void parseSelectedCiphersuite(ServerHelloMessage message) {
        message.setSelectedCipherSuite(parseByteArrayField(HandshakeByteLength.CIPHER_SUITE));
    }

    /**
     * Reads the next bytes as a CompressionMethod and writes them in the message
     *
     * @param message Message to write in
     */
    protected void parseSelectedComressionMethod(ServerHelloMessage message) {
        message.setSelectedCompressionMethod(parseByteField(HandshakeByteLength.COMPRESSION));
    }
}
