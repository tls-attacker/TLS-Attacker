/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SSL2MessageSerializer<T extends SSL2Message>
        extends ProtocolMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2MessageSerializer(T ssl2HandshakeMessage) {
        super(ssl2HandshakeMessage);
    }

    @Override
    protected byte[] serializeBytes() {
        writeMessageLength();
        writeType();
        return serializeMessageContent();
    }

    protected abstract byte[] serializeMessageContent();

    private void writeMessageLength() {
        if (message.getPaddingLength().getValue() != 0) {
            throw new UnsupportedOperationException("Long record headers are not supported");
        }
        appendInt(message.getMessageLength().getValue() ^ 0x8000, SSL2ByteLength.LENGTH);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

    protected void writeType() {
        appendByte(message.getType().getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }
}
