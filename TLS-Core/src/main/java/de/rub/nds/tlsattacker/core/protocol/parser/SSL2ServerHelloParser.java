/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerHelloParser extends SSL2MessageParser<SSL2ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerHelloParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SSL2ServerHelloMessage message) {
        LOGGER.debug("Parsing SSL2ServerHello");

        parseSessionIdHit(message);
        parseCertificateType(message);
        parseProtocolVersion(message);
        parseCertificateLength(message);
        parseCipherSuitesLength(message);
        parseSessionIDLength(message);
        parseCertificate(message);
        parseCipherSuites(message);
        parseSessionID(message);
    }

    /**
     * Reads the next bytes as the SessionIdHit and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseSessionIdHit(SSL2ServerHelloMessage message) {
        message.setSessionIdHit(parseByteField(SSL2ByteLength.SESSION_ID_HIT));
        LOGGER.debug("SessionIdHit: " + message.getSessionIdHit().getValue());
    }

    /**
     * Reads the next bytes as the CertificateType and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseCertificateType(SSL2ServerHelloMessage message) {
        message.setCertificateType(parseByteField(SSL2ByteLength.CERTIFICATE_TYPE));
        LOGGER.debug("CertificateType: " + message.getCertificateType().getValue());
    }

    /**
     * Reads the next bytes as the ProtocolVersion and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseProtocolVersion(SSL2ServerHelloMessage message) {
        message.setProtocolVersion(parseByteArrayField(SSL2ByteLength.VERSION));
        LOGGER.debug("ProtocolVersion: {}", message.getProtocolVersion().getValue());
    }

    /**
     * Reads the next bytes as the CertificateLength and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseCertificateLength(SSL2ServerHelloMessage message) {
        message.setCertificateLength(parseIntField(SSL2ByteLength.CERTIFICATE_LENGTH));
        LOGGER.debug("CertificateLength: " + message.getCertificateLength().getValue());
    }

    /**
     * Reads the next bytes as the CipherSuitesLength and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseCipherSuitesLength(SSL2ServerHelloMessage message) {
        message.setCipherSuitesLength(parseIntField(SSL2ByteLength.CIPHERSUITE_LENGTH));
        LOGGER.debug("CipherSuitesLength: " + message.getCipherSuitesLength().getValue());
    }

    /**
     * Reads the next bytes as the SessionIDLength and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseSessionIDLength(SSL2ServerHelloMessage message) {
        message.setSessionIDLength(parseIntField(SSL2ByteLength.SESSIONID_LENGTH));
        LOGGER.debug("SessionIDLength: " + message.getSessionIdLength().getValue());
    }

    /**
     * Reads the next bytes as the Certificate and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseCertificate(SSL2ServerHelloMessage message) {
        message.setCertificate(parseByteArrayField(message.getCertificateLength().getValue()));
        LOGGER.debug("Certificate: {}", message.getCertificate().getValue());
    }

    /**
     * Reads the next bytes as the CipherSuites and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseCipherSuites(SSL2ServerHelloMessage message) {
        message.setCipherSuites(parseByteArrayField(message.getCipherSuitesLength().getValue()));
        LOGGER.debug("CipherSuites: {}", message.getCipherSuites().getValue());
    }

    /**
     * Reads the next bytes as the SessionID and writes them in the message
     *
     * @param message Message to write in
     */
    private void parseSessionID(SSL2ServerHelloMessage message) {
        message.setSessionID(parseByteArrayField(message.getSessionIdLength().getValue()));
        LOGGER.debug("SessionID: {}", message.getSessionId().getValue());
    }
}
