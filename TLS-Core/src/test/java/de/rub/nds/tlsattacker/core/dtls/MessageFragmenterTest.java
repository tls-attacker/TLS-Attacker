/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParserTest;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

public class MessageFragmenterTest {

    public static Stream<Arguments> provideTestVectors() {
        Stream<Arguments> data = ClientHelloParserTest.provideTestVectors();
        return data.map(args -> {
            Object[] obj = args.get();
            obj[0] = ProtocolVersion.DTLS12;
            List<Object> list = new ArrayList<>();
            list.add(ProtocolVersion.DTLS12);
            list.add(obj[1]);
            // noinspection unchecked
            list.addAll((List<Object>) obj[2]);
            list.set(4, ProtocolVersion.DTLS12.getValue());
            return Arguments.of(list.toArray());
        });
    }

    private TlsContext tlsContext;
    private ClientHelloMessage clientMessage;

    @BeforeEach
    public void setUp() {
        tlsContext = new TlsContext();
        clientMessage = new ClientHelloMessage(Config.createConfig());
    }

    /**
     * Test of fragmentMessage method, of class MessageFragmenter with maxFragmentLenth given.
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void fragmentMessageTestLength(ProtocolVersion version, byte[] message, Byte type, int length,
        byte[] protocolVersion, byte[] unixTime, byte[] random, int sessionIdLength, byte[] sessionId,
        int cipherSuitesLength, byte[] cipherSuites, int compressionsLength, byte[] compressions,
        Integer extensionsLength, byte[] extensionBytes, Integer cookieLength, byte[] cookie) throws IOException {
        prepareClientMessage(message, type, length, protocolVersion, unixTime, random, sessionIdLength, sessionId,
            cipherSuitesLength, cipherSuites, compressionsLength, compressions, extensionsLength, extensionBytes,
            cookieLength, cookie);
        int maxFragmentLength = 128;
        List<DtlsHandshakeMessageFragment> fragmented =
            MessageFragmenter.fragmentMessage(clientMessage, maxFragmentLength, tlsContext);
        assertFragment(message, fragmented, maxFragmentLength);
    }

    /**
     * Test of fragmentMessage method, of class MessageFragmenter with prepared fragment list given.
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void fragmentMessageTestList(ProtocolVersion version, byte[] message, Byte type, int length,
        byte[] protocolVersion, byte[] unixTime, byte[] random, int sessionIdLength, byte[] sessionId,
        int cipherSuitesLength, byte[] cipherSuites, int compressionsLength, byte[] compressions,
        Integer extensionsLength, byte[] extensionBytes, Integer cookieLength, byte[] cookie) throws IOException {
        prepareClientMessage(message, type, length, protocolVersion, unixTime, random, sessionIdLength, sessionId,
            cipherSuitesLength, cipherSuites, compressionsLength, compressions, extensionsLength, extensionBytes,
            cookieLength, cookie);
        int maxFragmentLength = 64;
        List<DtlsHandshakeMessageFragment> fragments = new LinkedList<>();
        for (int i = 0; i < 4; i++) {
            DtlsHandshakeMessageFragment newFragment = new DtlsHandshakeMessageFragment();
            newFragment.setMaxFragmentLengthConfig(maxFragmentLength);
            fragments.add(newFragment);
        }
        List<DtlsHandshakeMessageFragment> fragmented =
            MessageFragmenter.fragmentMessage(clientMessage, fragments, tlsContext);
        assertFragment(message, fragmented, maxFragmentLength);
    }

    /**
     * Test of wrapInSingleFragment method, of class MessageFragmenter.
     */
    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void wrapInSingleFragmentTest(ProtocolVersion version, byte[] message, Byte type, int length,
        byte[] protocolVersion, byte[] unixTime, byte[] random, int sessionIdLength, byte[] sessionId,
        int cipherSuitesLength, byte[] cipherSuites, int compressionsLength, byte[] compressions,
        Integer extensionsLength, byte[] extensionBytes, Integer cookieLength, byte[] cookie) {
        prepareClientMessage(message, type, length, protocolVersion, unixTime, random, sessionIdLength, sessionId,
            cipherSuitesLength, cipherSuites, compressionsLength, compressions, extensionsLength, extensionBytes,
            cookieLength, cookie);
        DtlsHandshakeMessageFragment fragment = MessageFragmenter.wrapInSingleFragment(clientMessage, tlsContext);
        int fragmentLength = fragment.getContent().getValue().length;
        assertEquals(fragmentLength, (int) fragment.getFragmentLength().getValue());
        assertEquals(0, (int) fragment.getFragmentOffset().getValue());
        assertEquals(HandshakeMessageType.CLIENT_HELLO.getValue(), fragment.getType().getValue().byteValue());
        assertEquals(0, (int) fragment.getMessageSeq().getValue());
        byte[] contentBytes = fragment.getContent().getValue();
        byte[] expectedContentBytes = Arrays.copyOfRange(message, 6, message.length);
        expectedContentBytes = ArrayConverter.concatenate(ProtocolVersion.DTLS12.getValue(), expectedContentBytes);
        assertArrayEquals(contentBytes, expectedContentBytes);
    }

    public void prepareClientMessage(byte[] message, Byte type, int length, byte[] protocolVersion, byte[] unixTime,
        byte[] random, int sessionIdLength, byte[] sessionId, int cipherSuitesLength, byte[] cipherSuites,
        int compressionsLength, byte[] compressions, Integer extensionsLength, byte[] extensionBytes,
        Integer cookieLength, byte[] cookie) {
        clientMessage.setLength(length);
        clientMessage.setType(type);
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
        clientMessage.setExtensionsLength(extensionsLength);
        clientMessage.setSessionId(sessionId);
        clientMessage.setSessionIdLength(sessionIdLength);
        clientMessage.setCompleteResultingMessage(message);
        clientMessage.setUnixTime(unixTime);
        clientMessage.setRandom(random);
        clientMessage.setProtocolVersion(protocolVersion);
    }

    private void assertFragment(byte[] expectedPart, List<DtlsHandshakeMessageFragment> fragmented,
        int maxFragmentLength) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        int fragmentOffset = 0;
        for (DtlsHandshakeMessageFragment fragment : fragmented) {
            int fragmentLength = fragment.getContent().getValue().length;
            assertEquals(fragmentLength, (int) fragment.getFragmentLength().getValue());
            assertTrue(fragmentLength <= maxFragmentLength);
            assertEquals(fragmentOffset, (int) fragment.getFragmentOffset().getValue());
            fragmentOffset += fragmentLength;
            assertEquals(HandshakeMessageType.CLIENT_HELLO.getValue(), fragment.getType().getValue().byteValue());
            assertEquals(0, (int) fragment.getMessageSeq().getValue());
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
}
