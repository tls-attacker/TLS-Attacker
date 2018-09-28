/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerHelloParser extends SSL2HandshakeMessageParser<SSL2ServerHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerHelloParser(byte[] message, int pointer, ProtocolVersion selectedProtocolVersion) {
        super(pointer, message, selectedProtocolVersion);
    }

    @Override
    protected SSL2ServerHelloMessage parseMessageContent() {
        LOGGER.debug("Parsing SSL2ServerHello");
        SSL2ServerHelloMessage message = new SSL2ServerHelloMessage();
        parseMessageLength(message);
        parseType(message);
        parseSessionIdHit(message);
        parseCertificateType(message);
        parseProtocolVersion(message);
        parseCertificateLength(message);
        parseCipherSuitesLength(message);
        parseSessionIDLength(message);
        parseCertificate(message);
        parseCipherSuites(message);
        parseSessionID(message);
        return message;
    }

    /**
     * Reads the next bytes as the SessionIdHit and writes them in the message
     *
     * @param message
     *            Message to write in
     */
    private void parseSessionIdHit(SSL2ServerHelloMessage message) {
        message.setSessionIdHit(parseByteField(SSL2ByteLength.SESSION_ID_HIT));
        LOGGER.debug("SessionIdHit: " + message.getSessionIdHit().getValue());
    }

    /**
     * Reads the next bytes as the CertificateType and writes them in the
     * message
     *
     * @param message
     *            Message to write in
     */
    private void parseCertificateType(SSL2ServerHelloMessage message) {
        message.setCertificateType(parseByteField(SSL2ByteLength.CERTIFICATE_TYPE));
        LOGGER.debug("CertificateType: " + message.getCertificateType().getValue());
    }

    /**
     * Reads the next bytes as the ProtocolVersion and writes them in the
     * message
     *
     * @param message
     *            Message to write in
     */
    private void parseProtocolVersion(SSL2ServerHelloMessage message) {
        message.setProtocolVersion(parseByteArrayField(SSL2ByteLength.VERSION));
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
    }

    /**
     * Reads the next bytes as the CertificateLength and writes them in the
     * message
     *
     * @param message
     *            Message to write in
     */
    private void parseCertificateLength(SSL2ServerHelloMessage message) {
        message.setCertificateLength(parseIntField(SSL2ByteLength.CERTIFICATE_LENGTH));
        LOGGER.debug("CertificateLength: " + message.getCertificateLength().getValue());
    }

    /**
     * Reads the next bytes as the CipherSuitesLength and writes them in the
     * message
     *
     * @param message
     *            Message to write in
     */
    private void parseCipherSuitesLength(SSL2ServerHelloMessage message) {
        message.setCipherSuitesLength(parseIntField(SSL2ByteLength.CIPHERSUITE_LENGTH));
        LOGGER.debug("CipherSuitesLength: " + message.getCipherSuitesLength().getValue());
    }

    /**
     * Reads the next bytes as the SessionIDLength and writes them in the
     * message
     *
     * @param message
     *            Message to write in
     */
    private void parseSessionIDLength(SSL2ServerHelloMessage message) {
        message.setSessionIDLength(parseIntField(SSL2ByteLength.SESSIONID_LENGTH));
        LOGGER.debug("SessionIDLength: " + message.getSessionIdLength().getValue());
    }

    /**
     * Reads the next bytes as the Certificate and writes them in the message
     *
     * @param message
     *            Message to write in
     */
    private void parseCertificate(SSL2ServerHelloMessage message) {
        message.setCertificate(parseByteArrayField(message.getCertificateLength().getValue()));
        LOGGER.debug("Certificate: " + ArrayConverter.bytesToHexString(message.getCertificate().getValue()));
    }

    /**
     * Reads the next bytes as the CipherSuites and writes them in the message
     *
     * @param message
     *            Message to write in
     */
    private void parseCipherSuites(SSL2ServerHelloMessage message) {
        message.setCipherSuites(parseByteArrayField(message.getCipherSuitesLength().getValue()));
        LOGGER.debug("CipherSuites: " + ArrayConverter.bytesToHexString(message.getCipherSuites().getValue()));
    }

    /**
     * Reads the next bytes as the SessionID and writes them in the message
     *
     * @param message
     *            Message to write in
     */
    private void parseSessionID(SSL2ServerHelloMessage message) {
        message.setSessionID(parseByteArrayField(message.getSessionIdLength().getValue()));
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(message.getSessionId().getValue()));
    }
}
