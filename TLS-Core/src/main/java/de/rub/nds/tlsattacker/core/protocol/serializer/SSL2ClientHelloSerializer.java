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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ClientHelloSerializer extends ProtocolMessageSerializer<SSL2ClientHelloMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SSL2ClientHelloMessage msg;

    public SSL2ClientHelloSerializer(SSL2ClientHelloMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing SSL2ClientHello");
        writeMessageLength(msg);
        writeType(msg);
        writeProtocolVersion(msg);
        writeCipherSuiteLength(msg);
        writeSessionIDLength(msg);
        writeChallengeLength(msg);
        writeCipherSuites(msg);
        writeSessionID(msg);
        writeChallenge(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the MessageLength of the SSL2ClientHello into the final byte[]
     */
    private void writeMessageLength(SSL2ClientHelloMessage msg) {
        appendInt(msg.getMessageLength().getValue() ^ 0x8000, SSL2ByteLength.LENGTH);
        LOGGER.debug("MessageLength: " + msg.getMessageLength().getValue());
    }

    /**
     * Writes the Type of the SSL2ClientHello into the final byte[]
     */
    private void writeType(SSL2ClientHelloMessage msg) {
        appendByte(msg.getType().getValue());
        LOGGER.debug("Type: " + msg.getType().getValue());
    }

    /**
     * Writes the ProtocolVersion of the SSL2ClientHello into the final byte[]
     */
    private void writeProtocolVersion(SSL2ClientHelloMessage msg) {
        appendBytes(msg.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

    /**
     * Writes the CipherSuitesLength of the SSL2ClientHello into the final
     * byte[]
     */
    private void writeCipherSuiteLength(SSL2ClientHelloMessage msg) {
        appendInt(msg.getCipherSuiteLength().getValue(), SSL2ByteLength.CIPHERSUITE_LENGTH);
        LOGGER.debug("CipherSuiteLength: " + msg.getCipherSuiteLength().getValue());
    }

    /**
     * Writes the SessionIDLength of the SSL2ClientHello into the final byte[]
     */
    private void writeSessionIDLength(SSL2ClientHelloMessage msg) {
        appendInt(msg.getSessionIdLength().getValue(), SSL2ByteLength.SESSIONID_LENGTH);
        LOGGER.debug("SessionIDLength: " + msg.getSessionIdLength().getValue());
    }

    /**
     * Writes the ChallengeLength of the SSL2ClientHello into the final byte[]
     */
    private void writeChallengeLength(SSL2ClientHelloMessage msg) {
        appendInt(msg.getChallengeLength().getValue(), SSL2ByteLength.CHALLENGE_LENGTH);
        LOGGER.debug("ChallengeLength: " + msg.getChallengeLength().getValue());
    }

    /**
     * Writes the CipherSuites of the SSL2ClientHello into the final byte[]
     */
    private void writeCipherSuites(SSL2ClientHelloMessage msg) {
        appendBytes(msg.getCipherSuites().getValue());
        LOGGER.debug("CipherSuites: " + ArrayConverter.bytesToHexString(msg.getCipherSuites().getValue()));
    }

    /**
     * Writes the SessionID of the SSL2ClientHello into the final byte[]
     */
    private void writeSessionID(SSL2ClientHelloMessage msg) {
        appendBytes(msg.getSessionId().getValue());
        LOGGER.debug("SessionID: " + ArrayConverter.bytesToHexString(msg.getSessionId().getValue()));
    }

    /**
     * Writes the Challenge of the SSL2ClientHello into the final byte[]
     */
    private void writeChallenge(SSL2ClientHelloMessage msg) {
        appendBytes(msg.getChallenge().getValue());
        LOGGER.debug("Challenge: " + ArrayConverter.bytesToHexString(msg.getChallenge().getValue()));
    }
}
