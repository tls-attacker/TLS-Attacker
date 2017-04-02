/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientHelloSerializer extends HelloMessageSerializer<ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private ClientHelloMessage msg;

    public ClientHelloSerializer(ClientHelloMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeProtocolVersion();
        writeUnixtime();
        writeRandom();
        writeSessionIDLength();
        writeSessionID();
        serializeCipherSuiteLength(msg);
        serializeCipherSuites(msg);
        serializeCompressionLength(msg);
        serializeCompressions(msg);
        if (hasExtensionLengthField()) {
            serializeExtensionLength(msg);
            if (hasExtensions()) {
                serializeExtensionBytes(msg);
            }
        }
        return getAlreadySerialized();
    }

    private void serializeCipherSuiteLength(ClientHelloMessage msg) {
        appendInt(msg.getCipherSuiteLength().getValue(), HandshakeByteLength.CIPHER_SUITES_LENGTH);
        LOGGER.debug("CipherSuiteLength: "+ msg.getCipherSuiteLength().getValue());
    }

    private void serializeCipherSuites(ClientHelloMessage msg) {
        appendBytes(msg.getCipherSuites().getValue());
        LOGGER.debug("CipherSuite: "+ Arrays.toString(msg.getCipherSuites().getValue()));
    }

    private void serializeCompressionLength(ClientHelloMessage msg) {
        appendInt(msg.getCompressionLength().getValue(), HandshakeByteLength.COMPRESSION_LENGTH);
        LOGGER.debug("CompressionLength: "+ msg.getCompressionLength().getValue());
    }

    private void serializeCompressions(ClientHelloMessage msg) {
        appendBytes(msg.getCompressions().getValue());
        LOGGER.debug("Compressions: "+ Arrays.toString(msg.getCompressions().getValue()));
    }

    private void serializeExtensionLength(ClientHelloMessage msg) {
        appendInt(msg.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        LOGGER.debug("ExtensionLength: "+ msg.getExtensionsLength().getValue());
    }

    private void serializeExtensionBytes(ClientHelloMessage msg) {
        appendBytes(msg.getExtensionBytes().getValue());
        LOGGER.debug("ExtensionBytes: "+ Arrays.toString(msg.getExtensionBytes().getValue()));
    }

}
