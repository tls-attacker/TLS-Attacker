/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.StdPlainPkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.TestPkcs1Oracle;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 *
 *
 */
public class BleichenbacherAttackPlaintextTest {

    private static final int PREMASTER_SECRET_LENGTH = 48;

    private TlsContext context;

    /**
     *
     */
    @Before
    public void setUp() {
        context = new TlsContext();
    }

    /**
     *
     * @throws Exception
     */
    @Test
    public void testBleichenbacherAttack() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        context.getBadSecureRandom().setSeed(0);
        keyPairGenerator.initialize(2048, context.getBadSecureRandom());
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        SecureRandom sr = new SecureRandom();
        byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
        sr.nextBytes(plainBytes);
        byte[] cipherBytes;

        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        cipherBytes = cipher.doFinal(plainBytes);

        cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] message = cipher.doFinal(cipherBytes);

        Pkcs1Oracle oracle = new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.TTT,
                cipher.getBlockSize());

        Bleichenbacher attacker = new Bleichenbacher(message, oracle, true);
        attacker.attack();
        BigInteger solution = attacker.getSolution();

        Assert.assertArrayEquals("The computed solution for Bleichenbacher must be equal to the original message",
                message, solution.toByteArray());
    }
}
