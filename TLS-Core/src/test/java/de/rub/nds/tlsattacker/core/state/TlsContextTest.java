/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class TlsContextTest {

    private Config config;
    private TlsContext tlsContext;

    private KeySet testKeySet;

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        config = Config.createConfig();
        tlsContext = new TlsContext(config);
        tlsContext.getChooser();

        testKeySet = new KeySet();
        testKeySet.setClientWriteKey(
                ArrayConverter.hexStringToByteArray(
                        "65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        testKeySet.setClientWriteMacSecret(new byte[0]);
        testKeySet.setClientWriteIv(
                ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        testKeySet.setServerWriteIv(new byte[12]);
        testKeySet.setServerWriteKey(new byte[16]);
        testKeySet.setServerWriteMacSecret(new byte[0]);
    }

    private void activateEncryptionInContext() {
        tlsContext.getContext().setConnection(new OutboundConnection());
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC")));
        tlsContext
                .getContext()
                .setLayerStack(
                        new LayerStack(tlsContext.getContext(), new RecordLayer(tlsContext)));

        tlsContext
                .getRecordLayer()
                .updateEncryptionCipher(
                        new RecordAEADCipher(
                                tlsContext,
                                new CipherState(
                                        tlsContext.getChooser().getSelectedProtocolVersion(),
                                        tlsContext.getChooser().getSelectedCipherSuite(),
                                        testKeySet,
                                        tlsContext.isExtensionNegotiated(
                                                ExtensionType.ENCRYPT_THEN_MAC))));
    }

    /** Test of getOutboundMaxRecordDataSize method, of class TlsContext. */
    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionInactiveNoExtensions() {
        final Integer result = tlsContext.getOutboundMaxRecordDataSize();
        assertEquals(config.getDefaultMaxRecordData(), (int) result);
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
        assertNull(tlsContext.getMaxFragmentLength());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionActiveNoExtensions() {
        activateEncryptionInContext();

        final Integer result = tlsContext.getOutboundMaxRecordDataSize();
        assertEquals(config.getDefaultMaxRecordData(), (int) result);
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
        assertNull(tlsContext.getMaxFragmentLength());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionInactiveMaxFragmentLength() {
        tlsContext.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = tlsContext.getOutboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionActiveMaxFragmentLength() {
        activateEncryptionInContext();
        tlsContext.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = tlsContext.getOutboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeRecordSizeLimitTLS12() {
        activateEncryptionInContext();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setOutboundRecordSizeLimit(1337);

        final Integer result = tlsContext.getOutboundMaxRecordDataSize();
        assertEquals(1337, (int) result);
        assertEquals(1337, (int) tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeRecordSizeLimitTLS13() {
        activateEncryptionInContext();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultAdditionalPadding(42);
        tlsContext.setOutboundRecordSizeLimit(1337);

        final Integer result = tlsContext.getOutboundMaxRecordDataSize();
        assertEquals((1337 - 1 - 42), (int) result);
        assertEquals(1337, (int) tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeRecordSizeLimitInvalidConfig() {
        activateEncryptionInContext();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultAdditionalPadding(42);
        tlsContext.setOutboundRecordSizeLimit(42);

        final Integer result = tlsContext.getOutboundMaxRecordDataSize();
        assertEquals(0, (int) result);
        assertEquals(42, (int) tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    /** Test of getOutboundMaxRecordDataSize method, of class TlsContext. */
    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionInactiveNoExtensions() {
        final Integer result = tlsContext.getInboundMaxRecordDataSize();
        assertEquals(config.getDefaultMaxRecordData(), (int) result);
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
        assertNull(tlsContext.getMaxFragmentLength());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionActiveNoExtensions() {
        activateEncryptionInContext();

        final Integer result = tlsContext.getInboundMaxRecordDataSize();
        assertEquals(config.getDefaultMaxRecordData(), (int) result);
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
        assertNull(tlsContext.getMaxFragmentLength());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionInactiveMaxFragmentLength() {
        tlsContext.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = tlsContext.getInboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionActiveMaxFragmentLength() {
        activateEncryptionInContext();
        tlsContext.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = tlsContext.getInboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeRecordSizeLimitTLS12() {
        activateEncryptionInContext();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        config.setAddRecordSizeLimitExtension(Boolean.TRUE);
        config.setInboundRecordSizeLimit(123);

        final Integer result = tlsContext.getInboundMaxRecordDataSize();
        assertEquals(123, (int) result);
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertTrue(config.isAddRecordSizeLimitExtension());
        assertEquals(123, (int) config.getInboundRecordSizeLimit());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeRecordSizeLimitTLS13() {
        activateEncryptionInContext();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultAdditionalPadding(42);
        config.setAddRecordSizeLimitExtension(Boolean.TRUE);
        config.setInboundRecordSizeLimit(123);

        final Integer result = tlsContext.getInboundMaxRecordDataSize();
        assertEquals((123 - 1 - 42), (int) result);
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertTrue(config.isAddRecordSizeLimitExtension());
        assertEquals(123, (int) config.getInboundRecordSizeLimit());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeRecordSizeLimitInvalidConfig() {
        activateEncryptionInContext();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultAdditionalPadding(123);
        config.setAddRecordSizeLimitExtension(Boolean.TRUE);
        config.setInboundRecordSizeLimit(123);

        final Integer result = tlsContext.getInboundMaxRecordDataSize();
        assertEquals(0, (int) result);
        assertNull(tlsContext.getOutboundRecordSizeLimit());
        assertEquals(123, (int) config.getInboundRecordSizeLimit());
    }
}
