/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ClientHelloPreparator extends HandshakeMessagePreparator<SSL2ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SSL2ClientHelloMessage message;

    public SSL2ClientHelloPreparator(Chooser chooser, SSL2ClientHelloMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        prepareHandshakeMessageContents();
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        LOGGER.debug("Prepare SSL2ClientHello");
        preparePaddingLength(message);
        prepareType(message);
        prepareProtocolVersion(message);
        // By Default we just set a fixed value with ssl2 cipher suites
        prepareCipherSuites(message);
        byte[] challenge = new byte[16];
        chooser.getContext().getRandom().nextBytes(challenge);
        prepareChallenge(message, challenge);
        prepareSessionID(message);
        prepareSessionIDLength(message);
        prepareChallengeLength(message);
        prepareCipherSuiteLength(message);
        int length = SSL2ByteLength.CHALLENGE_LENGTH + SSL2ByteLength.CIPHERSUITE_LENGTH + SSL2ByteLength.MESSAGE_TYPE
            + SSL2ByteLength.SESSIONID_LENGTH;
        length += message.getChallenge().getValue().length;
        length += message.getCipherSuites().getValue().length;
        length += message.getSessionId().getValue().length;
        length += message.getProtocolVersion().getValue().length;
        prepareMessageLength(message, length);
    }

    private void preparePaddingLength(SSL2ClientHelloMessage message) {
        message.setPaddingLength(0);
        LOGGER.debug("PaddingLength: " + message.getPaddingLength().getValue());
    }

    private void prepareType(SSL2ClientHelloMessage message) {
        message.setType(HandshakeMessageType.CLIENT_HELLO.getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    private void prepareProtocolVersion(SSL2ClientHelloMessage message) {
        message.setProtocolVersion(chooser.getConfig().getHighestProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
    }

    private void prepareCipherSuites(SSL2ClientHelloMessage message) {
        ByteArrayOutputStream cipherStream = new ByteArrayOutputStream();
        for (SSL2CipherSuite suite : SSL2CipherSuite.values()) {
            try {
                if (suite != SSL2CipherSuite.SSL_UNKNOWN_CIPHER) {
                    cipherStream.write(suite.getByteValue());
                }
            } catch (IOException ex) {
                throw new PreparationException(
                    "Could not prepare SSL2ClientHello. Failed to write Cipher suites into message", ex);
            }
        }
        message.setCipherSuites(cipherStream.toByteArray());
        LOGGER.debug("CipherSuites: " + ArrayConverter.bytesToHexString(message.getCipherSuites().getValue()));
    }

    private void prepareChallenge(SSL2ClientHelloMessage message, byte[] challenge) {
        message.setChallenge(challenge);
        LOGGER.debug("Challenge: " + ArrayConverter.bytesToHexString(message.getChallenge().getValue()));
    }

    private void prepareSessionID(SSL2ClientHelloMessage message) {
        message.setSessionID(chooser.getClientSessionId());
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(message.getSessionId().getValue()));
    }

    private void prepareSessionIDLength(SSL2ClientHelloMessage message) {
        message.setSessionIDLength(message.getSessionId().getValue().length);
        LOGGER.debug("SessionIDLength: " + message.getSessionIdLength().getValue());
    }

    private void prepareChallengeLength(SSL2ClientHelloMessage message) {
        message.setChallengeLength(message.getChallenge().getValue().length);
        LOGGER.debug("ChallengeLength: " + message.getChallengeLength().getValue());
    }

    private void prepareCipherSuiteLength(SSL2ClientHelloMessage message) {
        message.setCipherSuiteLength(message.getCipherSuites().getValue().length);
        LOGGER.debug("CipherSuiteLength: " + message.getCipherSuiteLength().getValue());
    }

    private void prepareMessageLength(SSL2ClientHelloMessage message, int length) {
        message.setMessageLength(length);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

}
