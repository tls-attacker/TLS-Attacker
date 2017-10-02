/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.StdPlainPkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.TestPkcs1Oracle;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class BleichenbacherAttackPlaintextTest {

    private static final int PREMASTER_SECRET_LENGTH = 48;

    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
    }

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

    @Test
    public void testBleichenbacherAttackSearchCiphertext() throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        FileInputStream fis = new FileInputStream("/home/juraj/Downloads/InstagramCert.crt");
        BufferedInputStream bis = new BufferedInputStream(fis);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(bis);
        System.out.println(cert.getPublicKey());

        String paddedPremasterSecret = "00020325F41D3EBAF8986DA712C82BCD4D554BF0B54023C29B624DE9EF9C2F931EFC580F9AFB081B12E107B1E805F2B4F5F0F1D00C2D0F62634670921C505867FF20F6A8335E98AF8725385586B41FEFF205B4E05A010823F78B5F8F5C02439CE8F67A781D90CBE6BF1AE7F2BC40A49709A06C0E31499BF02969CA42D203E566BCC696DE08FA0102A0FD2E2330B0964ABB7C443020DE1CAD09BFD6381FFB94DAAFBB90C4ED91A0613AD1DC4B4703AF84C1D63B1A876921C6D5869D61CCB98ED13AE6C09A13FC91E14922F301CF8BCF0003039D2F07D983FAA91B8F4E7265ECB815A7CBABC1450CB72B3C74107717AA24AC42F25B6C6784767D0E3546C4F72501";
        byte[] pms = ArrayConverter.hexStringToByteArray(paddedPremasterSecret);

        List<Long> results = new LinkedList<>();

        for (int i = 21; i < 40; i++) {
            pms[3] = (byte) i;
            Pkcs1Oracle oracle = new StdPlainPkcs1Oracle(cert.getPublicKey(), TestPkcs1Oracle.OracleType.FTT, 256);
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
            byte[] message = cipher.doFinal(pms);
            System.out.println(ArrayConverter.bytesToHexString(message, false));

            Bleichenbacher attacker = new Bleichenbacher(pms, oracle, true);
            attacker.attack();
            BigInteger solution = attacker.getSolution();
            System.out.println("Ciphertext: " + ArrayConverter.bytesToHexString(message, false).replace(" ", ""));
            System.out.println("Resulting solution: " + solution.toString(16));
            results.add(oracle.getNumberOfQueries());
        }

        for (Long l : results) {
            System.out.println(l);
        }
    }
}
