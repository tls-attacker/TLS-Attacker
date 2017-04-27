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
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientHelloSerializer extends HelloMessageSerializer<ClientHelloMessage> {

    private ClientHelloMessage msg;

    /**
     * Constructor for the ClientHelloSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public ClientHelloSerializer(ClientHelloMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeProtocolVersion();
        if(version != ProtocolVersion.TLS13) {
            writeUnixtime();
        }
        writeRandom();
        writeSessionIDLength();
        if(version != ProtocolVersion.TLS13) {
            writeSessionID();
        }
        writeCipherSuiteLength(msg);
        writeCipherSuites(msg);
        writeCompressionLength(msg);
        writeCompressions(msg);
        if (hasExtensionLengthField()) {
            writeExtensionLength(msg);
            if (hasExtensions()) {
                writeExtensionBytes(msg);
            }
        }
        return getAlreadySerialized();
    }

    /**
     * Writes the CihperSuiteLength of the ClientHelloMessage into the final
     * byte[]
     */
    private void writeCipherSuiteLength(ClientHelloMessage msg) {
        appendInt(msg.getCipherSuiteLength().getValue(), HandshakeByteLength.CIPHER_SUITES_LENGTH);
        LOGGER.debug("CipherSuiteLength: " + msg.getCipherSuiteLength().getValue());
    }

    /**
     * Writes the CihperSuites of the ClientHelloMessage into the final byte[]
     */
    private void writeCipherSuites(ClientHelloMessage msg) {
        appendBytes(msg.getCipherSuites().getValue());
        LOGGER.debug("CipherSuite: " + ArrayConverter.bytesToHexString(msg.getCipherSuites().getValue()));
    }

    /**
     * Writes the CompressionLength of the ClientHelloMessage into the final
     * byte[]
     */
    private void writeCompressionLength(ClientHelloMessage msg) {
        appendInt(msg.getCompressionLength().getValue(), HandshakeByteLength.COMPRESSION_LENGTH);
        LOGGER.debug("CompressionLength: " + msg.getCompressionLength().getValue());
    }

    /**
     * Writes the Compressions of the ClientHelloMessage into the final byte[]
     */
    private void writeCompressions(ClientHelloMessage msg) {
        appendBytes(msg.getCompressions().getValue());
        LOGGER.debug("Compressions: " + ArrayConverter.bytesToHexString(msg.getCompressions().getValue()));
    }

    /**
     * Writes the ExtensionLength of the ClientHelloMessage into the final
     * byte[]
     */
    private void writeExtensionLength(ClientHelloMessage msg) {
        appendInt(msg.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        LOGGER.debug("ExtensionLength: " + msg.getExtensionsLength().getValue());
    }

    /**
     * Writes the ExtensionBytes of the ClientHelloMessage into the final byte[]
     */
    private void writeExtensionBytes(ClientHelloMessage msg) {
        appendBytes(msg.getExtensionBytes().getValue());
        LOGGER.debug("ExtensionBytes: " + ArrayConverter.bytesToHexString(msg.getExtensionBytes().getValue()));
    }

}
