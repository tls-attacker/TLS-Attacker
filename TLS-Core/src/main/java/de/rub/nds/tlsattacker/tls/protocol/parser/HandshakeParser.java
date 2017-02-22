/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;

/**
 * An abstract Parser class for HandshakeMessages
 * @author Robert Merget - robert.merget@rub.de
 * @param <T> Type of the HandshakeMessages to parse
 */
public abstract class HandshakeParser<T extends HandshakeMessage> extends Parser<T> {

    /**
     * Constructor for the Parser class
     * @param pointer Position in the array where the HandshakeParser is supposed to start parsing
     * @param array The byte[] which the HandshakeParser is supposed to parse
     */
    public HandshakeParser(int pointer, byte[] array) {
        super(pointer, array);
    }
    
    /**
     * Reads the next bytes as a HandshakeMessageType and writes them in the message
     * @param message Message to write in
     */
    protected void parseType(HandshakeMessage message) {
        message.setType(parseByteField(HandshakeByteLength.MESSAGE_TYPE));
    }

    /**
     * Reads the next bytes as the MessageLength and writes them in the message
     * @param message Message to write in
     */
    protected void parseLength(HandshakeMessage message) {
        message.setLength(parseIntField(HandshakeByteLength.MESSAGE_LENGTH_FIELD));
    }
}
