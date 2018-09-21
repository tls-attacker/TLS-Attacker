/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerHelloSerializer extends ProtocolMessageSerializer<SSL2ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SSL2ServerHelloMessage message;

    public SSL2ServerHelloSerializer(SSL2ServerHelloMessage message, TlsContext tlsContext) {
        super(message, tlsContext.getChooser().getSelectedProtocolVersion());
        this.message = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serialize SSL2ServerHello");
        writeMessageLength(message);
        writeType(message);
        writeSessionIdHit(message);
        writeCetificateType(message);
        writeProtocolVersion(message);
        writeCertificateLength(message);
        writeCipherSuitesLength(message);
        writeSessionIDLength(message);
        writeCertificate(message);
        writeCipherSuites(message);
        writeSessionID(message);
        return getAlreadySerialized();
    }

    /**
     * Writes the MessageLength of the SSL2ServerHello into the final byte[]
     */
    private void writeMessageLength(SSL2ServerHelloMessage message) {
        appendInt(message.getMessageLength().getValue(), SSL2ByteLength.LENGTH);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

    /**
     * Writes the Type of the SSL2ServerHello into the final byte[]
     */
    private void writeType(SSL2ServerHelloMessage message) {
        appendByte(message.getType().getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    /**
     * Writes the SessionIdHit of the SSL2ServerHello into the final byte[]
     */
    private void writeSessionIdHit(SSL2ServerHelloMessage message) {
        appendByte(message.getSessionIdHit().getValue());
        LOGGER.debug("SessionIdHit: " + message.getSessionIdHit().getValue());
    }

    /**
     * Writes the CertificateType of the SSL2ServerHello into the final byte[]
     */
    private void writeCetificateType(SSL2ServerHelloMessage message) {
        appendByte(message.getCertificateType().getValue());
        LOGGER.debug("CertificateType: " + message.getCertificateType().getValue());
    }

    /**
     * Writes the ProtocolVersion of the SSL2ServerHello into the final byte[]
     */
    private void writeProtocolVersion(SSL2ServerHelloMessage message) {
        appendBytes(message.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
    }

    /**
     * Writes the CertificateLength of the SSL2ServerHello into the final byte[]
     */
    private void writeCertificateLength(SSL2ServerHelloMessage message) {
        appendInt(message.getCertificateLength().getValue(), SSL2ByteLength.CERTIFICATE_LENGTH);
        LOGGER.debug("CertificateLength: " + message.getCertificateLength().getValue());
    }

    /**
     * Writes the CipherSuitesLength of the SSL2ServerHello into the final
     * byte[]
     */
    private void writeCipherSuitesLength(SSL2ServerHelloMessage message) {
        appendInt(message.getCipherSuitesLength().getValue(), SSL2ByteLength.CIPHERSUITE_LENGTH);
        LOGGER.debug("ChipherSuitesLength: " + message.getCipherSuitesLength().getValue());
    }

    /**
     * Writes the SessionIDLength of the SSL2ServerHello into the final byte[]
     */
    private void writeSessionIDLength(SSL2ServerHelloMessage message) {
        appendInt(message.getSessionIdLength().getValue(), SSL2ByteLength.SESSIONID_LENGTH);
        LOGGER.debug("SessionIDLength: " + message.getSessionIdLength().getValue());
    }

    /**
     * Writes the Certificate of the SSL2ServerHello into the final byte[]
     */
    private void writeCertificate(SSL2ServerHelloMessage message) {
        appendBytes(message.getCertificate().getValue());
        LOGGER.debug("Certificate: " + ArrayConverter.bytesToHexString(message.getCertificate().getValue()));
    }

    /**
     * Writes the CipherSuites of the SSL2ServerHello into the final byte[]
     */
    private void writeCipherSuites(SSL2ServerHelloMessage message) {
        appendBytes(message.getCipherSuites().getValue());
        LOGGER.debug("CipherSuites: " + ArrayConverter.bytesToHexString(message.getCipherSuites().getValue()));
    }

    /**
     * Writes the SessionID of the SSL2ServerHello into the final byte[]
     */
    private void writeSessionID(SSL2ServerHelloMessage message) {
        appendBytes(message.getSessionId().getValue());
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(message.getSessionId().getValue()));
    }

}
