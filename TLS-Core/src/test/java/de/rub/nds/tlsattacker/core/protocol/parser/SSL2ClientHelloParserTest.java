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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SSL2ClientHelloParserTest {

    /*
     * Constructing a SSL2 ClientHelloMessage, captured from www.aspray24.com
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("802b0100020012000000100100800700c0030080060040020080040080bc4c7de14f6fc8bff4428f159fb24f2b"),
                        ProtocolVersion.SSL2, 43, HandshakeMessageType.CLIENT_HELLO, ProtocolVersion.SSL2.getValue(),
                        18/* 0x0012 */, 0, 16/* 0x0010 */,
                        ArrayConverter.hexStringToByteArray("0100800700c0030080060040020080040080"), new byte[0],
                        ArrayConverter.hexStringToByteArray("bc4c7de14f6fc8bff4428f159fb24f2b") } });
    }

    private final byte[] message;
    private final ProtocolVersion version;
    private final int messageLength;
    private final HandshakeMessageType type;
    private final byte[] protocolVersion;
    private final int cipherSuiteLength;
    private final int sessionIdLength;
    private final int challengeLength;
    private final byte[] cipherSuites;
    private final byte[] sessionId;
    private final byte[] challenge;

    public SSL2ClientHelloParserTest(byte[] message, ProtocolVersion version, int messageLength,
            HandshakeMessageType type, byte[] protocolVersion, int cipherSuiteLength, int sessionIdLength,
            int challengeLength, byte[] cipherSuites, byte[] sessionId, byte[] challenge) {
        this.message = message;
        this.version = version;
        this.messageLength = messageLength;
        this.type = type;
        this.protocolVersion = protocolVersion;
        this.cipherSuiteLength = cipherSuiteLength;
        this.sessionIdLength = sessionIdLength;
        this.challengeLength = challengeLength;
        this.cipherSuites = cipherSuites;
        this.sessionId = sessionId;
        this.challenge = challenge;
    }

    /**
     * Test of parse method, of class SSL2ClientHelloParser.
     */
    @Test
    public void testParse() {
        SSL2ClientHelloParser parser = new SSL2ClientHelloParser(0, message, version);
        SSL2ClientHelloMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getMessageLength().getValue() == messageLength);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertArrayEquals(protocolVersion, msg.getProtocolVersion().getValue());
        assertTrue(msg.getCipherSuiteLength().getValue() == cipherSuiteLength);
        assertTrue(msg.getSessionIdLength().getValue() == sessionIdLength);
        assertTrue(msg.getChallengeLength().getValue() == challengeLength);
        assertArrayEquals(cipherSuites, msg.getCipherSuites().getValue());
        assertArrayEquals(sessionId, msg.getSessionId().getValue());
        assertArrayEquals(challenge, msg.getChallenge().getValue());
    }
}
