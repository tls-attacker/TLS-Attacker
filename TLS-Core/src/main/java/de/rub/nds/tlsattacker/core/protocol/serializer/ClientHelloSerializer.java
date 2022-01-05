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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientHelloSerializer extends HelloMessageSerializer<ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ClientHelloMessage msg;

    /**
     * Constructor for the ClientHelloSerializer
     *
     * @param message
     *                Message that should be serialized
     * @param version
     *                Version of the Protocol
     */
    public ClientHelloSerializer(ClientHelloMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing ClientHelloMessage");
        writeProtocolVersion();
        writeRandom();
        writeSessionIDLength();
        writeSessionID();
        if (version.isDTLS()) {
            writeCookieLength(msg);
            writeCookie(msg);
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
     * Writes the DTLS CookieLength of the ClientHelloMessage into the final byte[]
     */
    private void writeCookieLength(ClientHelloMessage msg) {
        appendInt(msg.getCookieLength().getValue(), HandshakeByteLength.DTLS_COOKIE_LENGTH);
        LOGGER.debug("CookieLength: " + msg.getCookieLength().getValue());
    }

    /**
     * Writes the DTLS Cookie of the ClientHelloMessage into the final byte[]
     */
    private void writeCookie(ClientHelloMessage msg) {
        appendBytes(msg.getCookie().getValue());
        LOGGER.debug("Cookie: " + ArrayConverter.bytesToHexString(msg.getCookie().getValue()));
    }

    /**
     * Writes the CipherSuiteLength of the ClientHelloMessage into the final byte[]
     */
    private void writeCipherSuiteLength(ClientHelloMessage msg) {
        appendInt(msg.getCipherSuiteLength().getValue(), HandshakeByteLength.CIPHER_SUITES_LENGTH);
        LOGGER.debug("CipherSuiteLength: " + msg.getCipherSuiteLength().getValue());
    }

    /**
     * Writes the CipherSuites of the ClientHelloMessage into the final byte[]
     */
    private void writeCipherSuites(ClientHelloMessage msg) {
        appendBytes(msg.getCipherSuites().getValue());
        LOGGER.debug("CipherSuite: " + ArrayConverter.bytesToHexString(msg.getCipherSuites().getValue()));
    }

    /**
     * Writes the CompressionLength of the ClientHelloMessage into the final byte[]
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
     * Writes the ExtensionLength of the ClientHelloMessage into the final byte[]
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
