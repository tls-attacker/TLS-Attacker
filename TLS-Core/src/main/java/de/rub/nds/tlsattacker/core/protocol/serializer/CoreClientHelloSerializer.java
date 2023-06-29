/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class CoreClientHelloSerializer<T extends CoreClientHelloMessage>
        extends HelloMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final T msg;

    private final ProtocolVersion version;

    /**
     * Constructor for the ClientHelloSerializer
     *
     * @param message Message that should be serialized
     * @param version Version of the Protocol
     */
    public CoreClientHelloSerializer(T message, ProtocolVersion version) {
        super(message);
        this.msg = message;
        this.version = version;
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

    /** Writes the DTLS CookieLength of the ClientHelloMessage into the final byte[] */
    private void writeCookieLength(T msg) {
        appendInt(msg.getCookieLength().getValue(), HandshakeByteLength.DTLS_COOKIE_LENGTH);
        LOGGER.debug("CookieLength: " + msg.getCookieLength().getValue());
    }

    /** Writes the DTLS Cookie of the ClientHelloMessage into the final byte[] */
    private void writeCookie(T msg) {
        appendBytes(msg.getCookie().getValue());
        LOGGER.debug("Cookie: " + ArrayConverter.bytesToHexString(msg.getCookie().getValue()));
    }

    /** Writes the CipherSuiteLength of the ClientHelloMessage into the final byte[] */
    private void writeCipherSuiteLength(T msg) {
        appendInt(msg.getCipherSuiteLength().getValue(), HandshakeByteLength.CIPHER_SUITES_LENGTH);
        LOGGER.debug("CipherSuiteLength: " + msg.getCipherSuiteLength().getValue());
    }

    /** Writes the CipherSuites of the ClientHelloMessage into the final byte[] */
    private void writeCipherSuites(T msg) {
        appendBytes(msg.getCipherSuites().getValue());
        LOGGER.debug(
                "CipherSuite: "
                        + ArrayConverter.bytesToHexString(msg.getCipherSuites().getValue()));
    }

    /** Writes the CompressionLength of the ClientHelloMessage into the final byte[] */
    private void writeCompressionLength(T msg) {
        appendInt(msg.getCompressionLength().getValue(), HandshakeByteLength.COMPRESSION_LENGTH);
        LOGGER.debug("CompressionLength: " + msg.getCompressionLength().getValue());
    }

    /** Writes the Compressions of the ClientHelloMessage into the final byte[] */
    private void writeCompressions(T msg) {
        appendBytes(msg.getCompressions().getValue());
        LOGGER.debug(
                "Compressions: "
                        + ArrayConverter.bytesToHexString(msg.getCompressions().getValue()));
    }

    /** Writes the ExtensionLength of the ClientHelloMessage into the final byte[] */
    private void writeExtensionLength(T msg) {
        appendInt(msg.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        LOGGER.debug("ExtensionLength: " + msg.getExtensionsLength().getValue());
    }

    /** Writes the ExtensionBytes of the ClientHelloMessage into the final byte[] */
    private void writeExtensionBytes(T msg) {
        appendBytes(msg.getExtensionBytes().getValue());
        LOGGER.debug(
                "ExtensionBytes: "
                        + ArrayConverter.bytesToHexString(msg.getExtensionBytes().getValue()));
    }
}
