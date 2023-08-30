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
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ClientHelloParser extends SSL2MessageParser<SSL2ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ClientHelloParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SSL2ClientHelloMessage msg) {
        LOGGER.debug("Parsing SSL2ClientHello");

        parseProtocolVersion(msg);
        parseCipherSuiteLength(msg);
        parseSessionIDLength(msg);
        parseChallengeLength(msg);
        parseCipherSuites(msg);
        parseSessionID(msg);
        parseChallenge(msg);
    }

    /**
     * Reads the next bytes as the ProtocolVersion and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseProtocolVersion(SSL2ClientHelloMessage msg) {
        msg.setProtocolVersion(parseByteArrayField(SSL2ByteLength.VERSION));
        LOGGER.debug("ProtocolVersion: {}", msg.getProtocolVersion().getValue());
    }

    /**
     * Reads the next bytes as the CipherSuiteLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseCipherSuiteLength(SSL2ClientHelloMessage msg) {
        msg.setCipherSuiteLength(parseIntField(SSL2ByteLength.CIPHERSUITE_LENGTH));
        LOGGER.debug("CipherSuiteLength: " + msg.getCipherSuiteLength().getValue());
    }

    /**
     * Reads the next bytes as the SessionIDLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSessionIDLength(SSL2ClientHelloMessage msg) {
        msg.setSessionIDLength(parseIntField(SSL2ByteLength.SESSIONID_LENGTH));
        LOGGER.debug("SessionIDLength: " + msg.getSessionIdLength().getValue());
    }

    /**
     * Reads the next bytes as the ChallengeLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseChallengeLength(SSL2ClientHelloMessage msg) {
        msg.setChallengeLength(parseIntField(SSL2ByteLength.CHALLENGE_LENGTH));
        LOGGER.debug("ChallengeLength: " + msg.getChallengeLength().getValue());
    }

    /**
     * Reads the next bytes as the CipherSuites and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseCipherSuites(SSL2ClientHelloMessage msg) {
        msg.setCipherSuites(parseByteArrayField(msg.getCipherSuiteLength().getValue()));
        LOGGER.debug("CipherSuites: {}", msg.getCipherSuites().getValue());
    }

    /**
     * Reads the next bytes as the SessionID and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSessionID(SSL2ClientHelloMessage msg) {
        msg.setSessionID(parseByteArrayField(msg.getSessionIdLength().getValue()));
        LOGGER.debug("SessionID: {}", msg.getSessionId().getValue());
    }

    /**
     * Reads the next bytes as the Challenge and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseChallenge(SSL2ClientHelloMessage msg) {
        msg.setChallenge(parseByteArrayField(msg.getChallengeLength().getValue()));
        LOGGER.debug("Challenge: {}", msg.getChallenge().getValue());
    }
}
