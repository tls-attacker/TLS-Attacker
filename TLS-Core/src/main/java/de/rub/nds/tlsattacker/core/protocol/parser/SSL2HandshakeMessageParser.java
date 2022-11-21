/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2HandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SSL2HandshakeMessageParser<T extends SSL2HandshakeMessage> extends HandshakeMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2HandshakeMessageParser(int pointer, byte[] array, HandshakeMessageType type, ProtocolVersion version,
        Config config) {
        super(pointer, array, type, version, config);
    }

    /**
     * Reads the next bytes as the MessageLength and writes them in the message
     *
     * @param message
     *                Message to write in
     */
    protected void parseMessageLength(T message) {
        // The "wonderful" SSL2 message length field:
        // 2-byte header: RECORD-LENGTH = ((byte[0] & 0x7f) << 8)) | byte[1];
        // 3-byte header: RECORD-LENGTH = ((byte[0] & 0x3f) << 8)) | byte[1];
        // If most significant bit on first byte is set: 2-byte header.
        // O/w, 3-byte header.
        byte[] length;
        int mask;
        if ((peek() & (byte) 0x80) != 0) {
            length = parseByteArrayField(SSL2ByteLength.LENGTH);
            mask = 0x3f;
            message.setPaddingLength(0);
        } else {
            length = parseByteArrayField(SSL2ByteLength.LONG_LENGTH);
            mask = 0x7f;
            message.setPaddingLength((int) length[2]);
        }
        int intLength = ((length[0] & mask) << Bits.IN_A_BYTE) | (length[1] & 0xFF);
        message.setMessageLength(intLength);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

    /**
     * Reads the next bytes as the Type and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    protected void parseType(T msg) {
        msg.setType(parseByteField(SSL2ByteLength.MESSAGE_TYPE));
        LOGGER.debug("Type: " + msg.getType().getValue());
    }

}
