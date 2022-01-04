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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ClientHelloPreparatorTest {

    private TlsContext context;
    private ClientHelloMessage message;
    private ClientHelloPreparator preparator;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new ClientHelloMessage();
        this.preparator = new ClientHelloPreparator(context.getChooser(), message);
    }

    // TODO Test with extensions
    /**
     * Test of prepareHandshakeMessageContents method, of class ClientHelloPreparator.
     */
    @Test
    public void testPrepareNoCookie() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678l));
        List<CipherSuite> cipherSuiteList = new LinkedList<>();
        cipherSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        cipherSuiteList.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        List<CompressionMethod> methodList = new LinkedList<>();
        methodList.add(CompressionMethod.DEFLATE);
        methodList.add(CompressionMethod.NULL);
        context.getConfig().setDefaultClientSupportedCipherSuites(cipherSuiteList);
        context.getConfig().setDefaultClientSupportedCompressionMethods(methodList);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS11);
        context.getConfig().setDefaultClientSessionId(new byte[] { 0, 1, 2, 3 });
        preparator.prepare();
        assertArrayEquals(ArrayConverter.hexStringToByteArray("009AC02B"), message.getCipherSuites().getValue());
        assertTrue(4 == message.getCipherSuiteLength().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0100"), message.getCompressions().getValue());
        assertTrue(2 == message.getCompressionLength().getValue());
        assertNull(message.getCookie());
        assertNull(message.getCookieLength());
        assertArrayEquals(message.getProtocolVersion().getValue(), ProtocolVersion.TLS11.getValue());
        assertArrayEquals(message.getSessionId().getValue(), new byte[] { 0, 1, 2, 3 });
        assertTrue(4 == message.getSessionIdLength().getValue());
        assertArrayEquals(ArrayConverter.longToUint32Bytes(12345678l), message.getUnixTime().getValue());
        assertTrue(message.getExtensionsLength().getValue() == 0);
        assertTrue(message.getExtensionBytes().getValue().length == 0);
    }

    @Test
    public void testPrepareWithCookie() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678l));
        List<CipherSuite> cipherSuiteList = new LinkedList<>();
        cipherSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        cipherSuiteList.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        List<CompressionMethod> methodList = new LinkedList<>();
        methodList.add(CompressionMethod.DEFLATE);
        methodList.add(CompressionMethod.NULL);
        context.getConfig().setDefaultClientSupportedCipherSuites(cipherSuiteList);
        context.getConfig().setDefaultClientSupportedCompressionMethods(methodList);
        context.getConfig().setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS10);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.DTLS10);
        context.getConfig().setDefaultClientSessionId(new byte[] { 0, 1, 2, 3 });
        context.setDtlsCookie(new byte[] { 7, 6, 5 });
        preparator.prepare();
        assertArrayEquals(ArrayConverter.hexStringToByteArray("009AC02B"), message.getCipherSuites().getValue());
        assertTrue(4 == message.getCipherSuiteLength().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0100"), message.getCompressions().getValue());
        assertTrue(2 == message.getCompressionLength().getValue());
        assertArrayEquals(new byte[] { 7, 6, 5 }, message.getCookie().getValue());
        assertTrue(3 == message.getCookieLength().getValue());
        assertArrayEquals(message.getProtocolVersion().getValue(), ProtocolVersion.DTLS10.getValue());
        assertArrayEquals(message.getSessionId().getValue(), new byte[] { 0, 1, 2, 3 });
        assertTrue(4 == message.getSessionIdLength().getValue());
        assertArrayEquals(ArrayConverter.longToUint32Bytes(12345678l), message.getUnixTime().getValue());
        assertTrue(message.getExtensionsLength().getValue() == 0);
        assertTrue(message.getExtensionBytes().getValue().length == 0);

    }

    @Test
    public void testDtlsPrepareWithCookie() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678l));
        List<CipherSuite> cipherSuiteList = new LinkedList<>();
        cipherSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        cipherSuiteList.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        List<CompressionMethod> methodList = new LinkedList<>();
        methodList.add(CompressionMethod.DEFLATE);
        methodList.add(CompressionMethod.NULL);
        context.getConfig().setDefaultClientSupportedCipherSuites(cipherSuiteList);
        context.getConfig().setDefaultClientSupportedCompressionMethods(methodList);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.DTLS12);
        context.getConfig().setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);
        context.getConfig().setDefaultClientSessionId(new byte[] { 0, 1, 2, 3 });
        context.setDtlsCookie(new byte[] { 7, 6, 5 });
        preparator.prepare();
        assertArrayEquals(ArrayConverter.hexStringToByteArray("009AC02B"), message.getCipherSuites().getValue());
        assertTrue(4 == message.getCipherSuiteLength().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0100"), message.getCompressions().getValue());
        assertTrue(2 == message.getCompressionLength().getValue());
        assertArrayEquals(new byte[] { 7, 6, 5 }, message.getCookie().getValue());
        assertTrue(3 == message.getCookieLength().getValue());
        assertArrayEquals(message.getProtocolVersion().getValue(), ProtocolVersion.DTLS12.getValue());
        assertArrayEquals(message.getSessionId().getValue(), new byte[] { 0, 1, 2, 3 });
        assertTrue(4 == message.getSessionIdLength().getValue());
        assertArrayEquals(ArrayConverter.longToUint32Bytes(12345678l), message.getUnixTime().getValue());
        assertTrue(message.getExtensionsLength().getValue() == 0);
        assertTrue(message.getExtensionBytes().getValue().length == 0);

    }

    @Test
    public void testPrepareResumption() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678l));
        List<CipherSuite> cipherSuiteList = new LinkedList<>();
        cipherSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        cipherSuiteList.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        List<CompressionMethod> methodList = new LinkedList<>();
        methodList.add(CompressionMethod.DEFLATE);
        methodList.add(CompressionMethod.NULL);
        context.getConfig().setDefaultClientSupportedCipherSuites(cipherSuiteList);
        context.getConfig().setDefaultClientSupportedCompressionMethods(methodList);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS11);
        context.setClientSessionId(new byte[] { 0, 1, 2, 3 });
        preparator.prepare();
        assertArrayEquals(message.getSessionId().getValue(), new byte[] { 0, 1, 2, 3 });
        assertTrue(4 == message.getSessionIdLength().getValue());
    }

    @Test
    public void testPrepareTicketResumption() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678l));
        List<CipherSuite> cipherSuiteList = new LinkedList<>();
        cipherSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        cipherSuiteList.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        List<CompressionMethod> methodList = new LinkedList<>();
        methodList.add(CompressionMethod.DEFLATE);
        methodList.add(CompressionMethod.NULL);
        context.getConfig().setDefaultClientSupportedCipherSuites(cipherSuiteList);
        context.getConfig().setDefaultClientSupportedCompressionMethods(methodList);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS11);
        context.setClientSessionId(new byte[0]);
        TicketSession session = new TicketSession(new byte[] { 1, 1, 1, 1 }, new byte[] { 2, 2, 2, 2 });
        context.addNewSession(session);
        SessionTicketTLSExtensionMessage extensionMessage = new SessionTicketTLSExtensionMessage();
        message.addExtension(extensionMessage);
        preparator.prepare();
        assertArrayEquals(message.getSessionId().getValue(),
            context.getConfig().getDefaultClientTicketResumptionSessionId());
        assertTrue(context.getConfig().getDefaultClientTicketResumptionSessionId().length
            == message.getSessionIdLength().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
