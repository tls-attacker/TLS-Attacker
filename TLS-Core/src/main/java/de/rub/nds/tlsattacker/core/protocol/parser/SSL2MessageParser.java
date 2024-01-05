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
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SSL2MessageParser<T extends SSL2Message> extends ProtocolMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2MessageParser(InputStream stream, TlsContext tlsContext) {
        super(stream);
    }

    /**
     * Reads the next bytes as the MessageLength and writes them in the message
     *
     * @param message Message to write in
     */
    protected void parseMessageLength(T message) {
        // The "wonderful" SSL2 message length field:
        // 2-byte header: RECORD-LENGTH = ((byte[0] & 0x7f) << 8)) | byte[1];
        // 3-byte header: RECORD-LENGTH = ((byte[0] & 0x3f) << 8)) | byte[1];
        // If most significant bit on first byte is set: 2-byte header.
        // O/w, 3-byte header.
        byte[] length;
        int mask;
        byte[] firstTwoBytes = parseByteArrayField(SSL2ByteLength.LENGTH);
        if ((firstTwoBytes[0] & (byte) 0x80) != 0) {
            length = firstTwoBytes;
            mask = 0x3f;
            message.setPaddingLength(0);
        } else {
            // Parse remaining bytes
            length =
                    ArrayConverter.concatenate(
                            firstTwoBytes,
                            parseByteArrayField(
                                    SSL2ByteLength.LONG_LENGTH - SSL2ByteLength.LENGTH));
            mask = 0x7f;
            message.setPaddingLength((int) length[2]);
        }
        int intLength = ((length[0] & mask) << Bits.IN_A_BYTE) | (length[1] & 0xFF);
        message.setMessageLength(intLength);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    /**
     * Reads the next bytes as the Type and writes them in the message
     *
     * @param msg Message to write in
     */
    protected void parseType(T msg) {
        msg.setType(parseByteField(SSL2ByteLength.MESSAGE_TYPE));
        LOGGER.debug("Type: " + msg.getType().getValue());
    }
}
