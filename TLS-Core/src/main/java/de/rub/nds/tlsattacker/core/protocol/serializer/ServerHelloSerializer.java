/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** SerializerClass for ServerHelloMessages */
public class ServerHelloSerializer extends HelloMessageSerializer<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /** The message that should be serialized */
    private final ServerHelloMessage msg;

    /**
     * Constructor for the ServerHelloMessageSerializer
     *
     * @param message Message that should be serialized
     */
    public ServerHelloSerializer(ServerHelloMessage message) {
        super(message);
        this.msg = message;
    }

    /** Writes the SelectedCipher suite of the message into the final byte[] */
    protected void writeSelectedCipherSuite() {
        appendBytes(msg.getSelectedCipherSuite().getValue());
        LOGGER.debug("SelectedCipherSuite: {}", msg.getSelectedCipherSuite().getValue());
    }

    /** Writes the SelectedCompressionMethod of the message into the final byte[] */
    protected void writeSelectedCompressionMethod() {
        appendByte(msg.getSelectedCompressionMethod().getValue());
        LOGGER.debug("SelectedCompressionMethod: " + msg.getSelectedCompressionMethod().getValue());
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing ServerHelloMessage");
        writeProtocolVersion();
        writeRandom();
        writeSessionIDLength();
        writeSessionID();
        writeSelectedCipherSuite();
        writeSelectedCompressionMethod();
        if (hasExtensionLengthField()) {
            writeExtensionLength();
            if (hasExtensions()) {
                writeExtensionBytes();
            }
        }
        return getAlreadySerialized();
    }
}
