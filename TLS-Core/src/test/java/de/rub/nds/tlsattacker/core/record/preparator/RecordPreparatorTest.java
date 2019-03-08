/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordEncryptor;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class RecordPreparatorTest {

    private RecordCipher recordCipher;
    private TlsContext context;
    private Record record;
    private Encryptor encryptor;
    public RecordPreparator preparator;
    private RecordCompressor compressor;

    public RecordPreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        record = new Record();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of the prepare method for TLS 1.3, of class RecordPreparator.
     * 
     * @throws java.security.NoSuchAlgorithmException
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test
    public void testPrepare() throws NoSuchAlgorithmException, CryptoException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13_DRAFT21);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.getConfig().setPaddingLength(0);
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("4B63051EABCD514D7CB6D1899F472B9F56856B01BDBC5B733FBB47269E7EBDC2"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("ACC9DB33EE0968FAE7E06DAA34D642B146092CE7F9C9CF47670C66A0A6CE1C8C"));
        context.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        context.setConnection(new InboundConnection());
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        recordCipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        encryptor = new RecordEncryptor(recordCipher, context);
        compressor = new RecordCompressor(context);
        preparator = new RecordPreparator(context.getChooser(), record, encryptor, ProtocolMessageType.HANDSHAKE,
                compressor);
        preparator.prepare();
        assertTrue(ProtocolMessageType.getContentType(record.getContentType().getValue()) == ProtocolMessageType.APPLICATION_DATA);
        assertTrue(ProtocolMessageType.getContentType(record.getContentMessageType().getValue()) == ProtocolMessageType.HANDSHAKE);
        assertArrayEquals(record.getProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
        assertTrue(record.getComputations().getPaddingLength().getValue() == 0);
        assertArrayEquals(ArrayConverter.hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229"), record
                .getProtocolMessageBytes().getValue());
    }

}
