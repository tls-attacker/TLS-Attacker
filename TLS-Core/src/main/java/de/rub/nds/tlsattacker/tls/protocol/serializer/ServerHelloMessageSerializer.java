/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * SerializerClass for ServerHelloMessages
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerHelloMessageSerializer extends HelloMessageSerializer<ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    /**
     * The message that should be serialized
     */
    private final ServerHelloMessage message;

    /**
     * Constructor for the ServerHelloMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     */
    public ServerHelloMessageSerializer(ServerHelloMessage message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    /**
     * Writes the SelectedCiphersuite of the message into the final byte[]
     */
    protected void writeSelectedCiphersuite() {
        appendBytes(message.getSelectedCipherSuite().getValue());
    }

    /**
     * Writes the SelectedCompressionMethod of the message into the final byte[]
     */
    protected void writeSelectedComressionMethod() {
        appendByte(message.getSelectedCompressionMethod().getValue());
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeProtocolVersion();
        writeUnixtime();
        writeRandom();
        writeSessionIDLength();
        writeSessionID();
        writeSelectedCiphersuite();
        writeSelectedComressionMethod();
        if (hasExtensionLengthField()) {
            writeExtensionLength();
            if (hasExtensions()) {
                writeExtensionBytes();
            }
        }
        return getAlreadySerialized();
    }

}
