/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * SerializerClass for ServerHelloMessages
 */
public class ServerHelloSerializer extends HelloMessageSerializer<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * The message that should be serialized
     */
    private final ServerHelloMessage msg;

    /**
     * Constructor for the ServerHelloMessageSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */
    public ServerHelloSerializer(ServerHelloMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    /**
     * Writes the SelectedCipher suite of the message into the final byte[]
     */
    protected void writeSelectedCipherSuite() {
        appendBytes(msg.getSelectedCipherSuite().getValue());
        LOGGER
            .debug("SelectedCipherSuite: " + ArrayConverter.bytesToHexString(msg.getSelectedCipherSuite().getValue()));
    }

    /**
     * Writes the SelectedCompressionMethod of the message into the final byte[]
     */
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
