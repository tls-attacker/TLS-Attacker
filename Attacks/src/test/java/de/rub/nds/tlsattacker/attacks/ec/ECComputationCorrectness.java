/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.tls.crypto.ec.Curve;
import de.rub.nds.tlsattacker.tls.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.tls.crypto.ec.DivisionException;
import de.rub.nds.tlsattacker.tls.crypto.ec.ECComputer;
import de.rub.nds.tlsattacker.tls.crypto.ec.Point;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Random;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ECComputationCorrectness {

    public ECComputationCorrectness() {
	Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testCustomLoop256() throws Exception {

	String BAD_X = "8beb5987e05b06ed39b8f29c22b32f4215792a79d32012cc17b4149fccb93cad";
	String BAD_Y = "748e228ba2aa3f9749798c273838cd52f8959f6413a3391bfa569464da0ff0e6";
	String SECRET = "25091756309879652045519159642875354611257005804552159157";

	String namedCurve = "secp256r1";
	int iter = 1000;

	testCustomLoop(namedCurve, new BigInteger(BAD_X, 16), new BigInteger(BAD_Y, 16), new BigInteger(SECRET), iter);
    }

    @Test
    public void testCustomLoop192() throws Exception {

	// curve with modulo 613, bringing false results
	String BAD_X = "dab989fced6437da3ea53999a24a84bf3f019ee1e4275188";
	String BAD_Y = "d3f2b30e5ccdcf20c3aadfe0cd6e4422b75599b7e3703ce9";
	String SECRET = "25091756309879652045519159642875354611257005804552159157";

	String namedCurve = "secp192r1";
	int iter = 1000;

	testCustomLoop(namedCurve, new BigInteger(BAD_X, 16), new BigInteger(BAD_Y, 16), new BigInteger(SECRET), iter);
    }

    private void testCustomLoop(String namedCurve, BigInteger badX, BigInteger badY, BigInteger secret, int iterations)
	    throws Exception {
	// initialize java stuff
	KeyPairGenerator kpg;
	kpg = KeyPairGenerator.getInstance("EC");
	ECGenParameterSpec ecsp;
	ecsp = new ECGenParameterSpec(namedCurve);
	kpg.initialize(ecsp);

	// initialize custem curve computation
	Curve curve = CurveFactory.getNamedCurve(namedCurve);
	ECComputer ecc = new ECComputer();
	ecc.setCurve(curve);

	Point basePoint = new Point(badX, badY);

	// decryption key
	KeyPair kpU = kpg.genKeyPair();
	ECPublicKey ecPubKeyU = (ECPublicKey) kpU.getPublic();

	int correctComputations = 0;

	BigInteger x = secret;
	for (int i = 1; i < iterations; i++) {
	    x = x.add(BigInteger.ONE);
	    ECPublicKeySpec bpubs = new ECPublicKeySpec(new ECPoint(badX, badY), ecPubKeyU.getParams());
	    ECPrivateKeySpec bprivs = new ECPrivateKeySpec(x, ecPubKeyU.getParams());

	    KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");

	    KeyFactory kfa = KeyFactory.getInstance("EC");
	    ECPublicKey bpub = (ECPublicKey) kfa.generatePublic(bpubs);
	    ECPrivateKey bpriv = (ECPrivateKey) kfa.generatePrivate(bprivs);

	    ecdhV.init(bpriv);

	    ecc.setSecret(x);

	    BigInteger sunSecret = null;
	    try {
		ecdhV.doPhase(bpub, true);
		sunSecret = new BigInteger(1, ecdhV.generateSecret());
		System.out.println("[SUN] Secret " + x + ": 0x" + (sunSecret).toString(16).toUpperCase());
	    } catch (Exception e) {
		System.out.println("[SUN] Secret: null");
	    }

	    BigInteger cusSecret = null;
	    try {
		Point res = ecc.mul(basePoint, true);
		cusSecret = res.getX();
		System.out.println("[CUS] Secret " + x + ": 0x" + cusSecret.toString(16).toUpperCase());

		System.out.println();
	    } catch (Exception e) {
		System.out.println("[CUS] Secret: null");
	    }

	    if (sunSecret != null) {
		if (sunSecret.equals(cusSecret)) {
		    correctComputations++;
		}
	    }

	}

	System.out.println("Correct Computations: " + correctComputations + " / " + iterations);
	System.out.println("Secret length (bits): " + x.bitLength());
    }

    @Test
    public void testPoints() throws Exception {
	String namedCurve = "secp192r1";
	int iter = 10;
	List<ICEPoint> points = ICEPointReader.readPoints(namedCurve);
	for (ICEPoint p : points) {
	    System.out.println("-------------------");
	    System.out.println(p);
	    BigInteger secretBase = new BigInteger("2");
	    int pow = -1;
	    boolean identical = true;
	    while (identical) {
		pow += 8;
		BigInteger secret = secretBase.pow(pow).subtract(new BigInteger("5"));
		System.out.println("Using Secret (" + secret.bitLength() + " bits): " + secret);
		identical = resultsIdentical(namedCurve, p.getX(), p.getY(), secret, iter);
	    }
	}
    }

    @Test
    public void testPercentageCorrectnessForSun() throws Exception {
	String namedCurve = "secp256r1";
	int iterations = 100;
	int testedPoints = 6;
	List<ICEPoint> points = ICEPointReader.readPoints(namedCurve);
	int[] correctResults = new int[points.size()];
	for (int i = 0; i < iterations; i++) {
	    BigInteger secret = new BigInteger(192, new Random());
	    for (int j = 0; j < points.size(); j++) {
		ICEPoint p = points.get(j);
		if (resultsIdentical(namedCurve, p.getX(), p.getY(), secret, testedPoints)) {
		    correctResults[j]++;
		}
	    }
	    if (i % 10 == 0) {
		System.out.println("Running iteration nr " + i);
	    }
	}

	for (int j = 0; j < points.size(); j++) {
	    ICEPoint p = points.get(j);
	    double percentage = (double) correctResults[j] / (double) iterations;
	    System.out.println("Curve with order " + p.getOrder()
		    + " has success probability of valid computation [%]: " + (percentage * 100.0));
	}
	for (int j = 0; j < points.size(); j++) {
	    ICEPoint p = points.get(j);
	    double percentage = (double) correctResults[j] / (double) iterations;
	    System.out.println(p.getOrder() + " " + (percentage * 100.0));
	}
    }

    /**
     * Executes point multiplication with custom and java sun computation. In
     * case the results differ, returns false.
     * 
     * In case Sun returns null, the result is not observed (sun returns null,
     * by accident?)
     * 
     * @param namedCurve
     * @param badX
     * @param badY
     * @param secret
     * @param iter
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     */
    private boolean resultsIdentical(String namedCurve, BigInteger badX, BigInteger badY, BigInteger secret, int iter)
	    throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException,
	    InvalidKeyException {
	for (int i = 0; i < iter; i++) {
	    secret = secret.add(BigInteger.ONE);
	    BigInteger resultCustom = computeSecretWithCustomAlgorithm(namedCurve, badX, badY, secret);
	    BigInteger resultSun = computeSecretWithSunAlgorithm(namedCurve, badX, badY, secret);
	    // System.out.println(resultCustom);
	    // System.out.println(resultSun);

	    if (resultSun != null && !resultSun.equals(resultCustom)) {
		return false;
	    }
	}
	return true;
    }

    private BigInteger computeSecretWithCustomAlgorithm(String namedCurve, BigInteger badX, BigInteger badY,
	    BigInteger secret) {
	// initialize custem curve computation
	Curve curve = CurveFactory.getNamedCurve(namedCurve);
	ECComputer ecc = new ECComputer();
	ecc.setCurve(curve);
	ecc.setSecret(secret);
	Point basePoint = new Point(badX, badY);

	Point res;
	try {
	    res = ecc.mul(basePoint, true);
	    return res.getX();
	} catch (DivisionException e) {
	    return null;
	}
    }

    private BigInteger computeSecretWithSunAlgorithm(String namedCurve, BigInteger badX, BigInteger badY,
	    BigInteger secret) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
	    InvalidKeySpecException, InvalidKeyException {
	// initialize java stuff
	KeyPairGenerator kpg;
	kpg = KeyPairGenerator.getInstance("EC");
	ECGenParameterSpec ecsp;
	ecsp = new ECGenParameterSpec(namedCurve);
	kpg.initialize(ecsp);

	// decryption key
	KeyPair kpU = kpg.genKeyPair();
	ECPublicKey ecPubKeyU = (ECPublicKey) kpU.getPublic();

	ECPublicKeySpec bpubs = new ECPublicKeySpec(new ECPoint(badX, badY), ecPubKeyU.getParams());
	ECPrivateKeySpec bprivs = new ECPrivateKeySpec(secret, ecPubKeyU.getParams());

	KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");

	KeyFactory kfa = KeyFactory.getInstance("EC");
	ECPublicKey bpub = (ECPublicKey) kfa.generatePublic(bpubs);
	ECPrivateKey bpriv = (ECPrivateKey) kfa.generatePrivate(bprivs);

	ecdhV.init(bpriv);
	try {
	    ecdhV.doPhase(bpub, true);
	    return new BigInteger(1, ecdhV.generateSecret());
	} catch (InvalidKeyException | IllegalStateException e) {
	    return null;
	}
    }

    public void testCompute() {
	BigInteger badx = new BigInteger("c70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397d", 16);
	BigInteger bady = new BigInteger("4a2e0ded57a5156bb82eb4314c37fd4155395a7e51988af289cce531b9c17192", 16);
	BigInteger secret = new BigInteger("aa6c4535a832135f7d5934e6e0de35d7eaedf8352ee2450e127efd13379949b8", 16);
	BigInteger result = computeSecretWithCustomAlgorithm("secp256r1", badx, bady, secret);
	System.out.println(result.toString(16));
    }
}
