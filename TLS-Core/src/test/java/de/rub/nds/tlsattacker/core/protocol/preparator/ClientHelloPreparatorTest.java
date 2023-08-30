/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.impl.DtlsFragmentLayer;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ClientHelloPreparatorTest
        extends AbstractProtocolMessagePreparatorTest<ClientHelloMessage, ClientHelloPreparator> {

    public ClientHelloPreparatorTest() {
        super(ClientHelloMessage::new, ClientHelloMessage::new, ClientHelloPreparator::new);
    }

    // TODO Test with extensions
    /** Test of prepareHandshakeMessageContents method, of class ClientHelloPreparator. */
    @Test
    @Override
    public void testPrepare() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678L));
        List<CipherSuite> cipherSuiteList = new LinkedList<>();
        cipherSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        cipherSuiteList.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        List<CompressionMethod> methodList = new LinkedList<>();
        methodList.add(CompressionMethod.DEFLATE);
        methodList.add(CompressionMethod.NULL);
        context.getConfig().setDefaultClientSupportedCipherSuites(cipherSuiteList);
        context.getConfig().setDefaultClientSupportedCompressionMethods(methodList);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS11);
        context.getConfig().setDefaultClientSessionId(new byte[] {0, 1, 2, 3});
        preparator.prepare();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("009AC02B"),
                message.getCipherSuites().getValue());
        assertEquals(4, message.getCipherSuiteLength().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0100"), message.getCompressions().getValue());
        assertEquals(2, message.getCompressionLength().getValue());
        assertNull(message.getCookie());
        assertNull(message.getCookieLength());
        assertArrayEquals(
                message.getProtocolVersion().getValue(), ProtocolVersion.TLS11.getValue());
        assertArrayEquals(message.getSessionId().getValue(), new byte[] {0, 1, 2, 3});
        assertEquals(4, message.getSessionIdLength().getValue());
        assertArrayEquals(
                ArrayConverter.longToUint32Bytes(12345678L), message.getUnixTime().getValue());
        assertEquals(0, message.getExtensionsLength().getValue());
        assertEquals(0, message.getExtensionBytes().getValue().length);
    }

    @Test
    public void testPrepareWithCookie() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678L));
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
        context.getConfig().setDefaultClientSessionId(new byte[] {0, 1, 2, 3});
        context.setDtlsCookie(new byte[] {7, 6, 5});
        context.getContext()
                .setLayerStack(
                        new LayerStack(context.getContext(), new DtlsFragmentLayer(context)));
        preparator.prepare();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("009AC02B"),
                message.getCipherSuites().getValue());
        assertEquals(4, message.getCipherSuiteLength().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0100"), message.getCompressions().getValue());
        assertEquals(2, message.getCompressionLength().getValue());
        assertArrayEquals(new byte[] {7, 6, 5}, message.getCookie().getValue());
        assertEquals(3, (int) message.getCookieLength().getValue());
        assertArrayEquals(
                message.getProtocolVersion().getValue(), ProtocolVersion.DTLS10.getValue());
        assertArrayEquals(message.getSessionId().getValue(), new byte[] {0, 1, 2, 3});
        assertEquals(4, message.getSessionIdLength().getValue());
        assertArrayEquals(
                ArrayConverter.longToUint32Bytes(12345678L), message.getUnixTime().getValue());
        assertEquals(0, message.getExtensionsLength().getValue());
        assertEquals(0, message.getExtensionBytes().getValue().length);
    }

    @Test
    public void testDtlsPrepareWithCookie() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678L));
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
        context.getConfig().setDefaultClientSessionId(new byte[] {0, 1, 2, 3});
        context.setDtlsCookie(new byte[] {7, 6, 5});
        preparator.prepare();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("009AC02B"),
                message.getCipherSuites().getValue());
        assertEquals(4, message.getCipherSuiteLength().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0100"), message.getCompressions().getValue());
        assertEquals(2, message.getCompressionLength().getValue());
        assertArrayEquals(new byte[] {7, 6, 5}, message.getCookie().getValue());
        assertEquals(3, message.getCookieLength().getValue());
        assertArrayEquals(
                message.getProtocolVersion().getValue(), ProtocolVersion.DTLS12.getValue());
        assertArrayEquals(message.getSessionId().getValue(), new byte[] {0, 1, 2, 3});
        assertEquals(4, message.getSessionIdLength().getValue());
        assertArrayEquals(
                ArrayConverter.longToUint32Bytes(12345678L), message.getUnixTime().getValue());
        assertEquals(0, message.getExtensionsLength().getValue());
        assertEquals(0, message.getExtensionBytes().getValue().length);
    }

    @Test
    public void testPrepareResumption() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678L));
        List<CipherSuite> cipherSuiteList = new LinkedList<>();
        cipherSuiteList.add(CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        cipherSuiteList.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        List<CompressionMethod> methodList = new LinkedList<>();
        methodList.add(CompressionMethod.DEFLATE);
        methodList.add(CompressionMethod.NULL);
        context.getConfig().setDefaultClientSupportedCipherSuites(cipherSuiteList);
        context.getConfig().setDefaultClientSupportedCompressionMethods(methodList);
        context.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS11);
        context.setClientSessionId(new byte[] {0, 1, 2, 3});
        preparator.prepare();
        assertArrayEquals(message.getSessionId().getValue(), new byte[] {0, 1, 2, 3});
        assertEquals(4, (int) message.getSessionIdLength().getValue());
    }

    @Test
    public void testPrepareTicketResumption() {
        TimeHelper.setProvider(new FixedTimeProvider(12345678L));
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
        TicketSession session = new TicketSession(new byte[] {1, 1, 1, 1}, new byte[] {2, 2, 2, 2});
        context.addNewSession(session);
        SessionTicketTLSExtensionMessage extensionMessage = new SessionTicketTLSExtensionMessage();
        message.addExtension(extensionMessage);
        preparator.prepare();
        assertArrayEquals(
                message.getSessionId().getValue(),
                context.getConfig().getDefaultClientTicketResumptionSessionId());
        assertEquals(
                context.getConfig().getDefaultClientTicketResumptionSessionId().length,
                (int) message.getSessionIdLength().getValue());
    }
}
