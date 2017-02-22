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

/**
 * An abstract Parser class for Hello Messages
 * 
 * @author Robert Merget - robert.merget@rub.de
 * @param <T> Type of the HelloMessage to parse
 */
public abstract class HelloParser<T extends HelloMessage> extends HandshakeParser<T> {

    /**
     * Constructor for the Parser class
     * @param pointer Position in the array where the HelloParser is supposed to start parsing
     * @param array The byte[] which the HelloParser is supposed to parse
     */
    public HelloParser(int pointer, byte[] array) {
        super(pointer, array);
    }
    
    /**
     * Checks if the message has an ExtensionLength field, by checking if the value specified in the length field is
     * big enough to allow it.
     * @param message Message to check
     * @return True if the message has an Extension field
     */
    protected boolean hasExtensionLengthField(HelloMessage message) {
        return message.getLength().getValue() + HandshakeByteLength.MESSAGE_TYPE + HandshakeByteLength.MESSAGE_LENGTH_FIELD > getPointer() - getStartPoint();
    }

    /**
     * Checks if the ExtensionsLengthField has a value greater than Zero, eg. if there are Extensions present.
     * @param message Message to Check
     * @return True if the message has Extensions
     */
    protected boolean hasExtensions(HelloMessage message) {
        return message.getExtensionsLength().getValue() > 0;
    }

    /**
     * Reads the next bytes as a ProtocolVersion and writes them in the message
     * @param message Message to write in
     */
    protected void parseProtocolVersion(HelloMessage message) {
        message.setProtocolVersion(parseByteArrayField(HandshakeByteLength.VERSION));
    }

    /**
     * Reads the next bytes as a Unixtime and writes them in the message
     * @param message Message to write in
     */
    protected void parseUnixtime(HelloMessage message) {
        message.setUnixTime(parseByteArrayField(HandshakeByteLength.UNIX_TIME));
    }

    /**
     * Reads the next bytes as a the Random and writes them in the message
     * @param message Message to write in
     */
    protected void parseRandom(HelloMessage message) {
        message.setRandom(parseByteArrayField(HandshakeByteLength.RANDOM));
    }

    /**
     * Reads the next bytes as the SessionID length and writes them in the message
     * @param message Message to write in
     */
    protected void parseSessionIDLength(HelloMessage message) {
        message.setSessionIdLength(parseIntField(HandshakeByteLength.SESSION_ID_LENGTH));
    }

    /**
     * Reads the next bytes as the SessionID and writes them in the message
     * @param message Message to write in
     */
    protected void parseSessionID(HelloMessage message) {
        message.setSessionId(parseByteArrayField(message.getSessionIdLength().getOriginalValue()));
    }
    
    /**
     * Reads the next bytes as the ExtensionLength and writes them in the message
     * @param message Message to write in
     */
    protected void parseExtensionLength(HelloMessage message) {
        message.setExtensionsLength(parseIntField(HandshakeByteLength.EXTENSION_LENGTH));
    }

    /**
     * Reads the next bytes as the ExtensionBytes and writes them in the message
     * @param message Message to write in
     */
    protected void parseExtensionBytes(HelloMessage message) {
        message.setExtensionsLength(parseIntField(message.getExtensionsLength().getValue()));
    }
}
