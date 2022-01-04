/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class TlsContextTest {

    private Config config;

    private TlsContext context;

    private KeySet testKeySet;

    @Before
    public void setUp() {
        config = Config.createConfig();
        config.setRecordLayerType(RecordLayerType.RECORD);
        context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));
        assertNotNull(context.getChooser());

        Security.addProvider(new BouncyCastleProvider());
        testKeySet = new KeySet();
        testKeySet
            .setClientWriteKey(ArrayConverter.hexStringToByteArray("65B7DA726864D4184D75A549BF5C06AB20867846AF4434CC"));
        testKeySet.setClientWriteMacSecret(new byte[0]);
        testKeySet.setClientWriteIv(ArrayConverter.hexStringToByteArray("11223344556677889900AABB"));
        testKeySet.setServerWriteIv(new byte[12]);
        testKeySet.setServerWriteKey(new byte[16]);
        testKeySet.setServerWriteMacSecret(new byte[0]);
    }

    private void activateEncryptionInContext() {
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC")));
        context.getRecordLayer()
            .updateEncryptionCipher(new RecordAEADCipher(context,
                new CipherState(context.getChooser().getSelectedProtocolVersion(),
                    context.getChooser().getSelectedCipherSuite(), testKeySet,
                    context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC))));
    }

    /**
     * Test of getOutboundMaxRecordDataSize method, of class TlsContext.
     */
    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionInactiveNoExtensions() {
        final Integer result = context.getOutboundMaxRecordDataSize();
        assertTrue(result == config.getDefaultMaxRecordData());
        assertNull(context.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
        assertNull(context.getMaxFragmentLength());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionActiveNoExtensions() {
        activateEncryptionInContext();

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertTrue(result == config.getDefaultMaxRecordData());
        assertNull(context.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
        assertNull(context.getMaxFragmentLength());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionInactiveMaxFragmentLength() {
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(context.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionActiveMaxFragmentLength() {
        activateEncryptionInContext();
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(context.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeRecordSizeLimitTLS12() {
        activateEncryptionInContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setOutboundRecordSizeLimit(1337);

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertTrue(result == 1337);
        assertTrue(context.getOutboundRecordSizeLimit() == 1337);
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeRecordSizeLimitTLS13() {
        activateEncryptionInContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultAdditionalPadding(42);
        context.setOutboundRecordSizeLimit(1337);

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertTrue(result == (1337 - 1 - 42));
        assertTrue(context.getOutboundRecordSizeLimit() == 1337);
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeRecordSizeLimitInvalidConfig() {
        activateEncryptionInContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultAdditionalPadding(42);
        context.setOutboundRecordSizeLimit(42);

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertTrue(result == 0);
        assertTrue(context.getOutboundRecordSizeLimit() == 42);
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    /**
     * Test of getOutboundMaxRecordDataSize method, of class TlsContext.
     */
    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionInactiveNoExtensions() {
        final Integer result = context.getInboundMaxRecordDataSize();
        assertTrue(result == config.getDefaultMaxRecordData());
        assertNull(context.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
        assertNull(context.getMaxFragmentLength());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionActiveNoExtensions() {
        activateEncryptionInContext();

        final Integer result = context.getInboundMaxRecordDataSize();
        assertTrue(result == config.getDefaultMaxRecordData());
        assertNull(context.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
        assertNull(context.getMaxFragmentLength());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionInactiveMaxFragmentLength() {
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = context.getInboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(context.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionActiveMaxFragmentLength() {
        activateEncryptionInContext();
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = context.getInboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(context.getOutboundRecordSizeLimit());
        assertFalse(config.isAddRecordSizeLimitExtension());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeRecordSizeLimitTLS12() {
        activateEncryptionInContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        config.setAddRecordSizeLimitExtension(Boolean.TRUE);
        config.setInboundRecordSizeLimit(123);

        final Integer result = context.getInboundMaxRecordDataSize();
        assertTrue(result == 123);
        assertNull(context.getOutboundRecordSizeLimit());
        assertTrue(config.isAddRecordSizeLimitExtension());
        assertTrue(config.getInboundRecordSizeLimit() == 123);
    }

    @Test
    public void testGetInboundMaxRecordDataSizeRecordSizeLimitTLS13() {
        activateEncryptionInContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultAdditionalPadding(42);
        config.setAddRecordSizeLimitExtension(Boolean.TRUE);
        config.setInboundRecordSizeLimit(123);

        final Integer result = context.getInboundMaxRecordDataSize();
        assertTrue(result == (123 - 1 - 42));
        assertNull(context.getOutboundRecordSizeLimit());
        assertTrue(config.isAddRecordSizeLimitExtension());
        assertTrue(config.getInboundRecordSizeLimit() == 123);
    }

    @Test
    public void testGetInboundMaxRecordDataSizeRecordSizeLimitInvalidConfig() {
        activateEncryptionInContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setDefaultAdditionalPadding(123);
        config.setAddRecordSizeLimitExtension(Boolean.TRUE);
        config.setInboundRecordSizeLimit(123);

        final Integer result = context.getInboundMaxRecordDataSize();
        assertTrue(result == 0);
        assertNull(context.getOutboundRecordSizeLimit());
        assertTrue(config.getInboundRecordSizeLimit() == 123);
    }
}
