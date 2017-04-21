/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParserTest;
import java.util.Collection;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class ClientHelloSerializerTest {

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;
    private byte[] protocolVersion;
    private byte[] unixtime;
    private byte[] random;
    private int sessionIdLength;
    private byte[] sessionID;
    private int cipherSuitesLength;
    private byte[] cipherSuites;
    private int compressionsLength;
    private byte[] compressions;
    private Integer extensionLength;
    private byte[] extensionBytes;
    private Byte cookieLength;
    private byte[] cookie;
    private int numberOfExtensions;

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ClientHelloParserTest.generateData();
    }

    public ClientHelloSerializerTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, byte[] protocolVersion, byte[] unixtime, byte[] random, int sessionIdLength, byte[] sessionID,
            int cipherSuitesLength, byte[] cipherSuites, int compressionsLength, byte[] compressions,
            Integer extensionLength, byte[] extensionBytes, Byte cookieLength, byte[] cookie, int numberOfExtensions) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.protocolVersion = protocolVersion;
        this.unixtime = unixtime;
        this.random = random;
        this.sessionIdLength = sessionIdLength;
        this.sessionID = sessionID;
        this.cipherSuitesLength = cipherSuitesLength;
        this.cipherSuites = cipherSuites;
        this.compressionsLength = compressionsLength;
        this.compressions = compressions;
        this.extensionLength = extensionLength;
        this.extensionBytes = extensionBytes;
        this.cookieLength = cookieLength;
        this.cookie = cookie;
        this.numberOfExtensions = numberOfExtensions;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * ClientHelloSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        ClientHelloMessage clientMessage = new ClientHelloMessage();
        clientMessage.setLength(length);
        clientMessage.setType(type.getValue());
        clientMessage.setCipherSuiteLength(cipherSuitesLength);
        clientMessage.setCipherSuites(cipherSuites);
        clientMessage.setCompressionLength(compressionsLength);
        clientMessage.setCompressions(compressions);
        if (cookie != null) {
            clientMessage.setCookie(cookie);
        }
        if (cookieLength != null) {
            clientMessage.setCookieLength(cookieLength);
        }
        if (extensionBytes != null) {
            clientMessage.setExtensionBytes(extensionBytes);
        }
        clientMessage.setExtensionsLength(extensionLength);
        clientMessage.setSessionId(sessionID);
        clientMessage.setSessionIdLength(sessionIdLength);
        clientMessage.setCompleteResultingMessage(expectedPart);
        clientMessage.setUnixTime(unixtime);
        clientMessage.setRandom(random);
        clientMessage.setProtocolVersion(protocolVersion);
        ClientHelloSerializer serializer = new ClientHelloSerializer(clientMessage, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }
}
