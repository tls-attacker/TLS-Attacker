/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.Security;
import java.util.Objects;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

public class TlsContextTest {

    private Config config;

    private KeySet testKeySet;

    @Before
    public void setUp() {
        config = Config.createConfig();
        config.setRecordLayerType(RecordLayerType.RECORD);

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

    private void activateEncryptionInContext(TlsContext context) {
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setRandom(new TestRandomData(ArrayConverter.hexStringToByteArray("FFEEDDCC")));
        context.getRecordLayer().setRecordCipher(new RecordAEADCipher(context, testKeySet));
    }

    /**
     * Test of getOutboundMaxRecordDataSize method, of class TlsContext.
     */
    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionInactiveNoExtensions() {
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertTrue(result == config.getDefaultMaxRecordData());
        assertNull(context.getOutboundRecordSizeLimit());
        assertNull(context.getInboundRecordSizeLimit());
        assertNull(context.getMaxFragmentLength());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionActiveNoExtensions() {
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));
        activateEncryptionInContext(context);

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertTrue(result == config.getDefaultMaxRecordData());
        assertNull(context.getOutboundRecordSizeLimit());
        assertNull(context.getInboundRecordSizeLimit());
        assertNull(context.getMaxFragmentLength());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionInactiveMaxFragmentLength() {
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(context.getOutboundRecordSizeLimit());
        assertNull(context.getInboundRecordSizeLimit());
    }

    @Test
    public void testGetOutboundMaxRecordDataSizeEncryptionActiveMaxFragmentLength() {
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));
        activateEncryptionInContext(context);
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = context.getOutboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(context.getOutboundRecordSizeLimit());
        assertNull(context.getInboundRecordSizeLimit());
    }

    /**
     * Test of getOutboundMaxRecordDataSize method, of class TlsContext.
     */
    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionInactiveNoExtensions() {
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));

        final Integer result = context.getInboundMaxRecordDataSize();
        assertTrue(result == config.getDefaultMaxRecordData());
        assertNull(context.getOutboundRecordSizeLimit());
        assertNull(context.getInboundRecordSizeLimit());
        assertNull(context.getMaxFragmentLength());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionActiveNoExtensions() {
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));
        activateEncryptionInContext(context);

        final Integer result = context.getInboundMaxRecordDataSize();
        assertTrue(result == config.getDefaultMaxRecordData());
        assertNull(context.getOutboundRecordSizeLimit());
        assertNull(context.getInboundRecordSizeLimit());
        assertNull(context.getMaxFragmentLength());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionInactiveMaxFragmentLength() {
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = context.getInboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(context.getOutboundRecordSizeLimit());
        assertNull(context.getInboundRecordSizeLimit());
    }

    @Test
    public void testGetInboundMaxRecordDataSizeEncryptionActiveMaxFragmentLength() {
        TlsContext context = new TlsContext(config);
        context.setRecordLayer(new TlsRecordLayer(context));
        activateEncryptionInContext(context);
        context.setMaxFragmentLength(MaxFragmentLength.TWO_11);

        final Integer result = context.getInboundMaxRecordDataSize();
        assertEquals(result, MaxFragmentLength.getIntegerRepresentation(MaxFragmentLength.TWO_11));
        assertNull(context.getOutboundRecordSizeLimit());
        assertNull(context.getInboundRecordSizeLimit());
    }
}
