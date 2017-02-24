/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;

/**
 * SerializerClass for ServerHelloMessages
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerHelloMessageSerializer extends HelloMessageSerializer<ServerHelloMessage> {

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
    public ServerHelloMessageSerializer(ServerHelloMessage message) {
        super(message);
        this.message = message;
    }

    /**
     * Writes the fields in the correct order into the Message
     */
    @Override
    protected void serializeBytes() {
        writeType();
        writeLength();
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

}
