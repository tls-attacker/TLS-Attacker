/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerHelloPreparator extends ProtocolMessagePreparator<SSL2ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerHelloPreparator(Chooser chooser, SSL2ServerHelloMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Prepare SSL2ServerHello");
        preparePaddingLength(message);
        prepareType(message);
        prepareProtocolVersion(message);

        prepareSessionIdHit(message);
        prepareSessionId(message);
        prepareSessionIdLength(message);

        prepareCertificate(message);
        prepareCertificateLength(message);
        prepareCertificateType(message);

        prepareCipherSuites(message);
        prepareCipherSuitesLength(message);

        prepareMessageLength(message);
    }

    private void prepareMessageLength(SSL2ServerHelloMessage message) {
        int length =
                SSL2ByteLength.SESSIONID_LENGTH
                        + SSL2ByteLength.CERTIFICATE_LENGTH
                        + SSL2ByteLength.CIPHERSUITE_LENGTH
                        + SSL2ByteLength.MESSAGE_TYPE
                        + SSL2ByteLength.SESSION_ID_HIT
                        + SSL2ByteLength.CERTIFICATE_TYPE;
        length += message.getCipherSuites().getValue().length;
        length += message.getSessionId().getValue().length;
        length += message.getProtocolVersion().getValue().length;
        length += message.getCertificateLength().getValue();
        message.setMessageLength(length);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

    private void prepareCertificate(SSL2ServerHelloMessage message) {
        CertificateMessage certificateMessage = new CertificateMessage();
        certificateMessage.getPreparator(chooser.getContext().getTlsContext()).prepare();
        certificateMessage.getCertificatesListBytes();
        message.setCertificate(certificateMessage.getCertificatesListBytes());
        LOGGER.debug("Certificate: " + message.getCertificate());
    }

    private void prepareSessionIdLength(SSL2ServerHelloMessage message) {
        message.setSessionIDLength(0);
        LOGGER.debug("SessionIDLength: " + message.getSessionIdLength());
    }

    private void prepareSessionId(SSL2ServerHelloMessage message) {
        message.setSessionID(new byte[0]);
        LOGGER.debug("SessionID: " + message.getSessionId());
    }

    private void prepareCipherSuitesLength(SSL2ServerHelloMessage message) {
        message.setCipherSuitesLength(message.getCipherSuites().getValue().length);
        LOGGER.debug("CipherSuiteLength: " + message.getCertificateLength());
    }

    private void prepareCertificateLength(SSL2ServerHelloMessage message) {
        message.setCertificateLength(message.getCertificate().getValue().length);
        LOGGER.debug("CertificateType: " + message.getCertificateLength());
    }

    private void prepareCertificateType(SSL2ServerHelloMessage message) {
        message.setCertificateType(chooser.getSelectedServerCertificateType().getValue());
        LOGGER.debug("CertificateType: " + message.getCertificateType().getValue());
    }

    private void prepareSessionIdHit(SSL2ServerHelloMessage message) {
        message.setSessionIdHit((byte) 0);
        LOGGER.debug("SessionIdHit: " + message.getSessionIdHit());
    }

    private void preparePaddingLength(SSL2ServerHelloMessage message) {
        message.setPaddingLength(0);
        LOGGER.debug("PaddingLength: " + message.getPaddingLength().getValue());
    }

    private void prepareType(SSL2ServerHelloMessage message) {
        message.setType(message.getSsl2MessageType().getType());
    }

    private void prepareProtocolVersion(SSL2ServerHelloMessage message) {
        message.setProtocolVersion(ProtocolVersion.SSL2.getValue());
    }

    private void prepareCipherSuites(SSL2ServerHelloMessage message) {
        ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();
        for (SSL2CipherSuite suite :
                chooser.getConfig().getDefaultServerSupportedSSL2CipherSuites()) {
            try {
                if (suite != SSL2CipherSuite.SSL_UNKNOWN_CIPHER) {
                    cipherStream.write(suite.getByteValue());
                }
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not prepare SSL2ClientHello. Failed to write Cipher suites into message",
                        ex);
            }
        }
        message.setCipherSuites(cipherStream.toByteArray());
        LOGGER.debug("CipherSuites: {}", message.getCipherSuites().getValue());
    }
}
