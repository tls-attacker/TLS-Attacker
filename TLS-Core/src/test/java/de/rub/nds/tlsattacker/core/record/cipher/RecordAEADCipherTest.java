/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola
 */
public class RecordAEADCipherTest {

    private TlsContext context;
    private RecordAEADCipher cipher;

    public RecordAEADCipherTest() {
    }

    @Before
    public void setUp() {
        this.context = new TlsContext();
    }

    /**
     * Test of the encrypt method, of class RecordAEADCipher.
     */
    @Test
    public void testEncrypt() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("6c6f274b1eae09b8bbd2039b7eb56147201a5e19288a3fd504fa52b1178a6e93"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("b2c2663ed59e833b17c68823516f11f1cb311855045d3ce46bfe8ac8889268d9"));
        context.getConfig().setConnectionEnd(ConnectionEnd.CLIENT);
        this.cipher = new RecordAEADCipher(context);
        byte[] plaintext = ArrayConverter
                .hexStringToByteArray("140000201a5eb0ba5f92f34ed0059d64cedd2a7d208f25f00e28138117fb3974d415776a16");
        byte[] ciphertext = cipher.encrypt(plaintext);
        byte[] ciphertext_correct = ArrayConverter
                .hexStringToByteArray("161e94818226d7bd6180630804644debc52bdd661034243217ac45a084228c82086baa4893ecfc969624d68e19d88c3e67ccb48bdf");
        assertArrayEquals(ciphertext, ciphertext_correct);
    }

    /**
     * Test of the decrypt method, of class RecordAEADCipher.
     */
    @Test
    public void testDecrypt() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setClientHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("6c6f274b1eae09b8bbd2039b7eb56147201a5e19288a3fd504fa52b1178a6e93"));
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("b2c2663ed59e833b17c68823516f11f1cb311855045d3ce46bfe8ac8889268d9"));
        context.getConfig().setConnectionEnd(ConnectionEnd.SERVER);
        this.cipher = new RecordAEADCipher(context);
        byte[] ciphertext = ArrayConverter
                .hexStringToByteArray("161e94818226d7bd6180630804644debc52bdd661034243217ac45a084228c82086baa4893ecfc969624d68e19d88c3e67ccb48bdf");
        byte[] plaintext = cipher.decrypt(ciphertext);
        byte[] plaintext_correct = ArrayConverter
                .hexStringToByteArray("140000201a5eb0ba5f92f34ed0059d64cedd2a7d208f25f00e28138117fb3974d415776a16");
        assertArrayEquals(plaintext, plaintext_correct);
    }
}
