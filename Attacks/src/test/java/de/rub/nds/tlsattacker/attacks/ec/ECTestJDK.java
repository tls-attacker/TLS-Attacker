/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import static de.rub.nds.tlsattacker.attacks.ec.ECComputationCorrectness.LOGGER;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Attack;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import javax.crypto.KeyAgreement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class ECTestJDK {

    static Logger LOGGER = LogManager.getLogger(ECTestJDK.class);

    public ECTestJDK() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGeneration() throws Exception {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC");
        LOGGER.info(kpg.getProvider());
        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        LOGGER.info(privKey.toString());
        LOGGER.info(pubKey.toString());
    }

    @Test
    public void testEnc() throws Exception {

        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecsp;

        ecsp = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecsp);

        KeyPair kpU = kpg.genKeyPair();

        PrivateKey privKeyU = kpU.getPrivate();
        PublicKey pubKeyU = kpU.getPublic();
        LOGGER.info("User U: " + privKeyU.toString());
        LOGGER.info("User U: " + pubKeyU.toString());
        KeyPair kpV = kpg.genKeyPair();
        PrivateKey privKeyV = kpV.getPrivate();
        PublicKey pubKeyV = kpV.getPublic();
        LOGGER.info("User V: " + privKeyV.toString());
        LOGGER.info("User V: " + pubKeyV.toString());
        KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
        ecdhU.init(privKeyU);
        ecdhU.doPhase(pubKeyV, true);
        KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
        ecdhV.init(privKeyV);
        ecdhV.doPhase(pubKeyU, true);
        LOGGER.info("Secret computed by U: 0x"
                + (new BigInteger(1, ecdhU.generateSecret("TlsPremasterSecret").getEncoded()).toString(16))
                        .toUpperCase());
        LOGGER.info("Secret computed by V: 0x" + (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
    }

    @Test
    public void testCustomLoop() throws Exception {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("secp192r1");
        kpg.initialize(ecsp);

        String BAD_X = "11ae802b7fe56f5304d66c34fc8eeada1d70498b0f54e88b";
        String BAD_Y = "5660e169994ec42f2bce4715b7acb081340c987b06db9e71";

        // decryption key
        KeyPair kpU = kpg.genKeyPair();
        ECPublicKey ecPubKeyU = (ECPublicKey) kpU.getPublic();
        BigInteger x = new BigInteger("5708409594436356196045493209041238753517241791310830494910");
        // BigInteger x = new BigInteger("0");
        for (int i = 1; i < 1_000; i++) {

            x = x.add(BigInteger.ONE);
            ECPublicKeySpec bpubs = new ECPublicKeySpec(new ECPoint(new BigInteger(BAD_X, 16),
                    new BigInteger(BAD_Y, 16)), ecPubKeyU.getParams());

            ECPrivateKeySpec bprivs = new ECPrivateKeySpec(x, ecPubKeyU.getParams());

            KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");

            KeyFactory kfa = KeyFactory.getInstance("EC");
            ECPublicKey bpub = (ECPublicKey) kfa.generatePublic(bpubs);
            ECPrivateKey bpriv = (ECPrivateKey) kfa.generatePrivate(bprivs);

            ecdhV.init(bpriv);

            try {
                ecdhV.doPhase(bpub, true);
                LOGGER.info("Secret " + x + ": 0x"
                        + (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
            } catch (IllegalStateException | InvalidKeyException e) {
                LOGGER.info("Secret: null");
            }
        }
    }

    @Test
    public void testCustomLoop256() throws Exception {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecsp);

        String BAD_X = "115792089210356248762697446949407573529679828795292731072903511356852658151166";
        String BAD_Y = "41058363725152142129326129780047268409114441015993725554835256314039467401292";

        // decryption key
        KeyPair kpU = kpg.genKeyPair();
        ECPublicKey ecPubKeyU = (ECPublicKey) kpU.getPublic();

        // BigInteger x = new
        // BigInteger("5708409594436356196045493209041238753517241791310830494910");
        BigInteger x = new BigInteger("0");
        for (int i = 1; i < 100; i++) {

            x = x.add(BigInteger.ONE);
            ECPublicKeySpec bpubs = new ECPublicKeySpec(new ECPoint(new BigInteger(BAD_X, 10),
                    new BigInteger(BAD_Y, 10)), ecPubKeyU.getParams());

            ECPrivateKeySpec bprivs = new ECPrivateKeySpec(x, ecPubKeyU.getParams());

            KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");

            KeyFactory kfa = KeyFactory.getInstance("EC");
            ECPublicKey bpub = (ECPublicKey) kfa.generatePublic(bpubs);
            ECPrivateKey bpriv = (ECPrivateKey) kfa.generatePrivate(bprivs);

            ecdhV.init(bpriv);

            try {
                ecdhV.doPhase(bpub, true);
                LOGGER.info("Secret " + x + ": 0x"
                        + (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
            } catch (InvalidKeyException | IllegalStateException e) {
                LOGGER.info("Secret: null");
            }
        }
    }
}
