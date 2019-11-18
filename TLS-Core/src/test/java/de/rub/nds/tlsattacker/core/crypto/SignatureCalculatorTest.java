/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import static de.rub.nds.tlsattacker.core.constants.ProtocolVersion.SSL3;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class SignatureCalculatorTest {

    private TlsContext context;
    private byte[] data;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        context = new TlsContext();
        context.setConnection(new InboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        data = new byte[0];
    }

    @Test
    public void anonymousSignatureTest() throws CryptoException {
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.ANONYMOUS_SHA1;
        byte[] signature = SignatureCalculator.generateSignature(algorithm, context.getChooser(), new byte[0]);
        assertArrayEquals(signature, new byte[0]);
    }

    @Test
    public void RSASignatureTest() throws NoSuchAlgorithmException, CryptoException, InvalidKeyException,
            SignatureException {
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.RSA_SHA1;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, context.getBadSecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        context.setServerRSAPrivateKey(privateKey.getPrivateExponent());
        context.setServerRsaModulus(privateKey.getModulus());

        byte[] signature = SignatureCalculator.generateSignature(algorithm, context.getChooser(), data);
        Signature instance = Signature.getInstance(algorithm.getJavaName());
        instance.initVerify(keyPair.getPublic());
        instance.update(data);
        assertTrue(instance.verify(signature));
    }

    @Test
    public void RSASSSL3ignatureTest() throws NoSuchAlgorithmException, CryptoException, InvalidKeyException,
            SignatureException {
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.RSA_NONE;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, context.getBadSecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        context.setServerRSAPrivateKey(privateKey.getPrivateExponent());
        context.setServerRsaModulus(privateKey.getModulus());
        context.setSelectedProtocolVersion(SSL3);

        byte[] signature = SignatureCalculator.generateSignature(algorithm, context.getChooser(), data);
        Signature instance = Signature.getInstance("NONEwithRSA");
        instance.initVerify(keyPair.getPublic());
        instance.update(ArrayConverter.concatenate(MD5Utils.MD5(data), SHA1Utils.sha1(data)));
        assertTrue(instance.verify(signature));
    }

    @Test
    public void DSASignatureTest() throws NoSuchAlgorithmException, CryptoException, InvalidKeyException,
            SignatureException {
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.DSA_SHA1;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024, context.getBadSecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        DSAPrivateKey privateKey = (DSAPrivateKey) keyPair.getPrivate();
        context.setServerDsaPrivateKey(privateKey.getX());
        context.setServerDsaGenerator(privateKey.getParams().getG());
        context.setServerDsaPrimeP(privateKey.getParams().getP());
        context.setServerDsaPrimeQ(privateKey.getParams().getQ());

        byte[] signature = SignatureCalculator.generateSignature(algorithm, context.getChooser(), data);
        Signature instance = Signature.getInstance(algorithm.getJavaName());
        instance.initVerify(keyPair.getPublic());
        instance.update(new byte[0]);
        assertTrue(instance.verify(signature));
    }

    @Test
    public void ECDSASignatureTest() throws NoSuchAlgorithmException, CryptoException, InvalidKeyException,
            SignatureException {
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.ECDSA_SHA1;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
        keyPairGenerator.initialize(256, context.getBadSecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        context.setServerEcPrivateKey(privateKey.getS());
        context.setSelectedProtocolVersion(SSL3);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);

        byte[] signature = SignatureCalculator.generateSignature(algorithm, context.getChooser(), data);
        Signature instance = Signature.getInstance(algorithm.getJavaName());
        instance.initVerify(keyPair.getPublic());
        instance.update(new byte[0]);
        assertTrue(instance.verify(signature));
    }

    @Test
    public void ECDSASSL3SignatureTest() throws NoSuchAlgorithmException, CryptoException, InvalidKeyException,
            SignatureException {
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.ECDSA_SHA1;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
        keyPairGenerator.initialize(256, context.getBadSecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        context.setServerEcPrivateKey(privateKey.getS());
        context.setSelectedProtocolVersion(SSL3);
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);

        byte[] signature = SignatureCalculator.generateSignature(algorithm, context.getChooser(), data);
        Signature instance = Signature.getInstance(algorithm.getJavaName());
        instance.initVerify(keyPair.getPublic());
        instance.update(new byte[0]);
        assertTrue(instance.verify(signature));
    }

    @Test
    public void Gost01SignatureTest() throws NoSuchAlgorithmException, CryptoException, InvalidKeyException,
            SignatureException, InvalidAlgorithmParameterException {
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.GOSTR34102001_GOSTR3411;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410");
        keyPairGenerator.initialize(new ECNamedCurveGenParameterSpec("GostR3410-2001-CryptoPro-XchB"),
                context.getBadSecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        BCECGOST3410PrivateKey privateKey = (BCECGOST3410PrivateKey) keyPair.getPrivate();
        context.setServerEcPrivateKey(privateKey.getS());

        byte[] signature = SignatureCalculator.generateSignature(algorithm, context.getChooser(), data);
        Signature instance = Signature.getInstance(algorithm.getJavaName());
        instance.initVerify(keyPair.getPublic());
        instance.update(new byte[0]);
        assertTrue(instance.verify(signature));
    }

    @Test
    public void Gost12SignatureTest() throws NoSuchAlgorithmException, CryptoException, InvalidKeyException,
            SignatureException, InvalidAlgorithmParameterException {
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.GOSTR34102012_512_GOSTR34112012_512;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410-2012");
        keyPairGenerator.initialize(new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"),
                context.getBadSecureRandom());
        context.getConfig().setDefaultSelectedGostCurve(GOSTCurve.Tc26_Gost_3410_12_512_paramSetA);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        BCECGOST3410_2012PrivateKey privateKey = (BCECGOST3410_2012PrivateKey) keyPair.getPrivate();
        context.setServerEcPrivateKey(privateKey.getS());
        byte[] signature = SignatureCalculator.generateSignature(algorithm, context.getChooser(), data);
        Signature instance = Signature.getInstance(algorithm.getJavaName());
        instance.initVerify(keyPair.getPublic());
        instance.update(new byte[0]);
        assertTrue(instance.verify(signature));
    }
}
