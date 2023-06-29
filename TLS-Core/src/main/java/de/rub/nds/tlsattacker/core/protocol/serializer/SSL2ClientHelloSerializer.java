/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ClientHelloSerializer extends SSL2MessageSerializer<SSL2ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ClientHelloSerializer(SSL2ClientHelloMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeMessageContent() {
        LOGGER.debug("Serializing SSL2ClientHello");
        writeProtocolVersion();
        writeCipherSuiteLength();
        writeSessionIDLength();
        writeChallengeLength();
        writeCipherSuites();
        writeSessionID();
        writeChallenge();
        return getAlreadySerialized();
    }

    /** Writes the ProtocolVersion of the SSL2ClientHello into the final byte[] */
    private void writeProtocolVersion() {
        appendBytes(message.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: {}", message.getProtocolVersion().getValue());
    }

    /** Writes the CipherSuitesLength of the SSL2ClientHello into the final byte[] */
    private void writeCipherSuiteLength() {
        appendInt(message.getCipherSuiteLength().getValue(), SSL2ByteLength.CIPHERSUITE_LENGTH);
        LOGGER.debug("CipherSuiteLength: " + message.getCipherSuiteLength().getValue());
    }

    /** Writes the SessionIDLength of the SSL2ClientHello into the final byte[] */
    private void writeSessionIDLength() {
        appendInt(message.getSessionIdLength().getValue(), SSL2ByteLength.SESSIONID_LENGTH);
        LOGGER.debug("SessionIDLength: " + message.getSessionIdLength().getValue());
    }

    /** Writes the ChallengeLength of the SSL2ClientHello into the final byte[] */
    private void writeChallengeLength() {
        appendInt(message.getChallengeLength().getValue(), SSL2ByteLength.CHALLENGE_LENGTH);
        LOGGER.debug("ChallengeLength: " + message.getChallengeLength().getValue());
    }

    /** Writes the CipherSuites of the SSL2ClientHello into the final byte[] */
    private void writeCipherSuites() {
        appendBytes(message.getCipherSuites().getValue());
        LOGGER.debug("CipherSuites: {}", message.getCipherSuites().getValue());
    }

    /** Writes the SessionID of the SSL2ClientHello into the final byte[] */
    private void writeSessionID() {
        appendBytes(message.getSessionId().getValue());
        LOGGER.debug("SessionID: {}", message.getSessionId().getValue());
    }

    /** Writes the Challenge of the SSL2ClientHello into the final byte[] */
    private void writeChallenge() {
        appendBytes(message.getChallenge().getValue());
        LOGGER.debug("Challenge: {}", message.getChallenge().getValue());
    }
}
