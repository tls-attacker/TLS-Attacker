/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParserTest;
import static org.junit.Assert.*;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Arrays;

@RunWith(Parameterized.class)
public class MessageFragmenterTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        Collection<Object[]> data = ClientHelloParserTest.generateData();
        for (Object[] obj : data) {
            obj[3] = ProtocolVersion.DTLS12;
            obj[4] = ProtocolVersion.DTLS12.getValue();
        }
        return data;
    }

    private final byte[] expectedPart;
    private final ProtocolVersion version;
    private final HandshakeMessageType type;
    private final int length;
    private final byte[] protocolVersion;
    private final byte[] unixTime;
    private final byte[] random;
    private final int sessionIdLength;
    private final byte[] sessionID;
    private final int cipherSuitesLength;
    private final byte[] cipherSuites;
    private final int compressionsLength;
    private final byte[] compressions;
    private final Integer extensionLength;
    private final byte[] extensionBytes;
    private final Byte cookieLength;
    private final byte[] cookie;

    private TlsContext tlsContext;
    private ClientHelloMessage clientMessage;

    public MessageFragmenterTest(byte[] message, HandshakeMessageType type, int length, ProtocolVersion version,
        byte[] protocolVersion, byte[] unixTime, byte[] random, int sessionIdLength, byte[] sessionID,
        int cipherSuitesLength, byte[] cipherSuites, int compressionsLength, byte[] compressions,
        Integer extensionLength, byte[] extensionBytes, Byte cookieLength, byte[] cookie, int numberOfExtensions) {
        this.expectedPart = message;
        this.type = type;
        this.length = length;
        this.version = version;
        this.protocolVersion = protocolVersion;
        this.unixTime = unixTime;
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
    }

    @Before
    public void setUp() {
        tlsContext = new TlsContext();
        clientMessage = new ClientHelloMessage(Config.createConfig());

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
        clientMessage.setUnixTime(unixTime);
        clientMessage.setRandom(random);
        clientMessage.setProtocolVersion(protocolVersion);
    }

    /**
     * Test of fragmentMessage method, of class MessageFragmenter with maxFragmentLenth given.
     */
    @Test
    public void fragmentMessageTestLength() throws IOException {
        int maxFragmentLength = 128;
        List<DtlsHandshakeMessageFragment> fragmented =
            MessageFragmenter.fragmentMessage(clientMessage, maxFragmentLength, tlsContext);
        testFragments(fragmented, maxFragmentLength);
    }

    /**
     * Test of fragmentMessage method, of class MessageFragmenter with prepared fragment list given.
     */
    @Test
    public void fragmentMessageTestList() throws IOException {
        int maxFragmentLength = 64;
        List<DtlsHandshakeMessageFragment> fragments = new LinkedList<>();
        for (int i = 0; i < 4; i++) {
            DtlsHandshakeMessageFragment newFragment = new DtlsHandshakeMessageFragment();
            newFragment.setMaxFragmentLengthConfig(maxFragmentLength);
            fragments.add(newFragment);
        }
        List<DtlsHandshakeMessageFragment> fragmented =
            MessageFragmenter.fragmentMessage(clientMessage, fragments, tlsContext);
        testFragments(fragmented, maxFragmentLength);
    }

    private void testFragments(List<DtlsHandshakeMessageFragment> fragmented, int maxFragmentLength)
        throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        int fragmentOffset = 0;
        for (DtlsHandshakeMessageFragment fragment : fragmented) {
            int fragmentLength = fragment.getContent().getValue().length;
            assertTrue(fragment.getFragmentLength().getValue() == fragmentLength);
            assertTrue(fragmentLength <= maxFragmentLength);
            assertTrue(fragment.getFragmentOffset().getValue() == fragmentOffset);
            fragmentOffset += fragmentLength;
            assertEquals(fragment.getType().getValue().byteValue(), HandshakeMessageType.CLIENT_HELLO.getValue());
            assertTrue(fragment.getMessageSeq().getValue() == 0);
            byte[] fragmentContent = fragment.getContent().getValue();
            if (fragmentContent != null) {
                byteStream.write(fragmentContent);
            }
        }
        byte[] contentBytes = byteStream.toByteArray();
        byte[] expectedContentBytes = Arrays.copyOfRange(expectedPart, 6, expectedPart.length);
        expectedContentBytes = ArrayConverter.concatenate(ProtocolVersion.DTLS12.getValue(), expectedContentBytes);
        assertArrayEquals(contentBytes, expectedContentBytes);
    }

    /**
     * Test of wrapInSingleFragment method, of class MessageFragmenter.
     */
    @Test
    public void wrapInSingleFragmentTest() {
        DtlsHandshakeMessageFragment fragment = MessageFragmenter.wrapInSingleFragment(clientMessage, tlsContext);
        int fragmentLength = fragment.getContent().getValue().length;
        assertTrue(fragment.getFragmentLength().getValue() == fragmentLength);
        assertTrue(fragment.getFragmentOffset().getValue() == 0);
        assertEquals(fragment.getType().getValue().byteValue(), HandshakeMessageType.CLIENT_HELLO.getValue());
        assertTrue(fragment.getMessageSeq().getValue() == 0);
        byte[] contentBytes = fragment.getContent().getValue();
        byte[] expectedContentBytes = Arrays.copyOfRange(expectedPart, 6, expectedPart.length);
        expectedContentBytes = ArrayConverter.concatenate(ProtocolVersion.DTLS12.getValue(), expectedContentBytes);
        assertArrayEquals(contentBytes, expectedContentBytes);
    }
}
