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
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerHelloSerializer extends HandshakeMessageSerializer<SSL2ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerHelloSerializer(SSL2ServerHelloMessage message, TlsContext tlsContext) {
        super(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        serializeHandshakeMessageContent();
        return getAlreadySerialized();
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serialize SSL2ServerHello");
        writeMessageLength();
        writeType();
        writeSessionIdHit();
        writeCertificateType();
        writeProtocolVersion();
        writeCertificateLength();
        writeCipherSuitesLength();
        writeSessionIDLength();
        writeCertificate();
        writeCipherSuites();
        writeSessionID();
        return getAlreadySerialized();
    }

    /**
     * Writes the MessageLength of the SSL2ServerHello into the final byte[]
     */
    private void writeMessageLength() {
        if (message.getPaddingLength().getValue() != 0) {
            throw new UnsupportedOperationException("Long record headers are not supported");
        }
        // TODO: This looks wrong, I'd assume the value has to be masked (see
        // e.g. SSL2ClientHelloSerializer)
        appendInt(message.getMessageLength().getValue(), SSL2ByteLength.LENGTH);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

    /**
     * Writes the Type of the SSL2ServerHello into the final byte[]
     */
    private void writeType() {
        appendByte(message.getType().getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    /**
     * Writes the SessionIdHit of the SSL2ServerHello into the final byte[]
     */
    private void writeSessionIdHit() {
        appendByte(message.getSessionIdHit().getValue());
        LOGGER.debug("SessionIdHit: " + message.getSessionIdHit().getValue());
    }

    /**
     * Writes the CertificateType of the SSL2ServerHello into the final byte[]
     */
    private void writeCertificateType() {
        appendByte(message.getCertificateType().getValue());
        LOGGER.debug("CertificateType: " + message.getCertificateType().getValue());
    }

    /**
     * Writes the ProtocolVersion of the SSL2ServerHello into the final byte[]
     */
    private void writeProtocolVersion() {
        appendBytes(message.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
    }

    /**
     * Writes the CertificateLength of the SSL2ServerHello into the final byte[]
     */
    private void writeCertificateLength() {
        appendInt(message.getCertificateLength().getValue(), SSL2ByteLength.CERTIFICATE_LENGTH);
        LOGGER.debug("CertificateLength: " + message.getCertificateLength().getValue());
    }

    /**
     * Writes the CipherSuitesLength of the SSL2ServerHello into the final byte[]
     */
    private void writeCipherSuitesLength() {
        appendInt(message.getCipherSuitesLength().getValue(), SSL2ByteLength.CIPHERSUITE_LENGTH);
        LOGGER.debug("CipherSuitesLength: " + message.getCipherSuitesLength().getValue());
    }

    /**
     * Writes the SessionIDLength of the SSL2ServerHello into the final byte[]
     */
    private void writeSessionIDLength() {
        appendInt(message.getSessionIdLength().getValue(), SSL2ByteLength.SESSIONID_LENGTH);
        LOGGER.debug("SessionIDLength: " + message.getSessionIdLength().getValue());
    }

    /**
     * Writes the Certificate of the SSL2ServerHello into the final byte[]
     */
    private void writeCertificate() {
        appendBytes(message.getCertificate().getValue());
        LOGGER.debug("Certificate: " + ArrayConverter.bytesToHexString(message.getCertificate().getValue()));
    }

    /**
     * Writes the CipherSuites of the SSL2ServerHello into the final byte[]
     */
    private void writeCipherSuites() {
        appendBytes(message.getCipherSuites().getValue());
        LOGGER.debug("CipherSuites: " + ArrayConverter.bytesToHexString(message.getCipherSuites().getValue()));
    }

    /**
     * Writes the SessionID of the SSL2ServerHello into the final byte[]
     */
    private void writeSessionID() {
        appendBytes(message.getSessionId().getValue());
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(message.getSessionId().getValue()));
    }

}
