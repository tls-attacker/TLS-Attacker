/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import javax.crypto.KeyAgreement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class ECTestJDK {

    public ECTestJDK() {
	Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGeneration() throws Exception {
	KeyPairGenerator kpg;
	kpg = KeyPairGenerator.getInstance("EC");
	System.out.println(kpg.getProvider());
	ECGenParameterSpec ecsp;
	ecsp = new ECGenParameterSpec("secp256r1");
	kpg.initialize(ecsp);

	KeyPair kp = kpg.genKeyPair();
	PrivateKey privKey = kp.getPrivate();
	PublicKey pubKey = kp.getPublic();

	System.out.println(privKey.toString());
	System.out.println(pubKey.toString());
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
	System.out.println("User U: " + privKeyU.toString());
	System.out.println("User U: " + pubKeyU.toString());
	KeyPair kpV = kpg.genKeyPair();
	PrivateKey privKeyV = kpV.getPrivate();
	PublicKey pubKeyV = kpV.getPublic();
	System.out.println("User V: " + privKeyV.toString());
	System.out.println("User V: " + pubKeyV.toString());
	KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
	ecdhU.init(privKeyU);
	ecdhU.doPhase(pubKeyV, true);
	KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
	ecdhV.init(privKeyV);
	ecdhV.doPhase(pubKeyU, true);
	System.out.println("Secret computed by U: 0x"
		+ (new BigInteger(1, ecdhU.generateSecret("TlsPremasterSecret").getEncoded()).toString(16))
			.toUpperCase());
	System.out.println("Secret computed by V: 0x"
		+ (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
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
	for (int i = 1; i < 1000; i++) {

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
		System.out.println("Secret " + x + ": 0x"
			+ (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
	    } catch (Exception e) {
		System.out.println("Secret: null");
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
		System.out.println("Secret " + x + ": 0x"
			+ (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
	    } catch (Exception e) {
		System.out.println("Secret: null");
	    }
	}
    }
}
