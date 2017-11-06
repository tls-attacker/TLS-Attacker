/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import org.junit.Before;
import org.junit.Test;

/**

 */
public class RecordAEADCipherTest {

    private TlsContext context;
    private RecordAEADCipher cipher;

    public RecordAEADCipherTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        this.context = new TlsContext();
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("4B63051EABCD514D7CB6D1899F472B9F56856B01BDBC5B733FBB47269E7EBDC2"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("ACC9DB33EE0968FAE7E06DAA34D642B146092CE7F9C9CF47670C66A0A6CE1C8C"));
    }

    /**
     * Test of the encrypt method, of class RecordAEADCipher.
     * 
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testEncrypt() throws NoSuchAlgorithmException {
        context.setConnectionEnd(new ServerConnectionEnd());
        this.cipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        byte[] plaintext = ArrayConverter.hexStringToByteArray("08000002000016");
        byte[] ciphertext = cipher.encrypt(new EncryptionRequest(plaintext)).getCompleteEncryptedCipherText();
        byte[] ciphertext_correct = ArrayConverter
                .hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229");
        assertArrayEquals(ciphertext, ciphertext_correct);
    }

    /**
     * Test of the decrypt method, of class RecordAEADCipher.
     * 
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testDecrypt() throws NoSuchAlgorithmException {
        context.setConnectionEnd(new ClientConnectionEnd());
        this.cipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        byte[] ciphertext = ArrayConverter.hexStringToByteArray("1BB3293A919E0D66F145AE830488E8D89BE5EC16688229");
        byte[] plaintext = cipher.decrypt(ciphertext);
        byte[] plaintext_correct = ArrayConverter.hexStringToByteArray("08000002000016");
        assertArrayEquals(plaintext, plaintext_correct);
    }

    @Test
    public void testInit() throws NoSuchAlgorithmException {
        context.setConnectionEnd(new ClientConnectionEnd());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13_DRAFT21);
        context.setHandshakeSecret(ArrayConverter
                .hexStringToByteArray("B2ED61DCDF8DD56D444A37827CF16C0C7D3AF4F95ACE1520746634F8EFED58E2"));
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("0DEE9BF2778DEE8AB18379C94B05C96F1ED1C28B3C51744180E2D47F97E46101"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("12756B2CA0395F1A1C3E268EF8610FBBAC8773E22F43BDABA385CE7E780A08B5"));

        this.cipher = new RecordAEADCipher(context, KeySetGenerator.generateKeySet(context));
        assertArrayEquals(ArrayConverter.hexStringToByteArray("B8FF433DBB565709C9A6703B"), cipher.getKeySet()
                .getClientWriteIv());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("549EC618891BCA1E676D9A60"), cipher.getKeySet()
                .getServerWriteIv());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("B176715B3DD8D62B26E9FB4F19FDDAF8"), cipher.getKeySet()
                .getClientWriteKey());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("7DD498D9EA924142CD3BF45CD8A1B4B9"), cipher.getKeySet()
                .getServerWriteKey());
        assertNull(cipher.getKeySet().getClientWriteMacSecret());
        assertNull(cipher.getKeySet().getServerWriteMacSecret());
    }
}
