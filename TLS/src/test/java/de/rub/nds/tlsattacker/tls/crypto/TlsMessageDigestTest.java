/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.logging.log4j.LogManager;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Robert Merget
 */
public class TlsMessageDigestTest {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(TlsMessageDigest.class);
    private TlsMessageDigest digest1; // TLS10
    private TlsMessageDigest digest2; // TLS12
    private String testAlgorithm1 = "MD5";
    private int testAlgorithm1Length = 16;
    private String testAlgorithm2 = "SHA1";
    private int testAlgorithm2Length = 20;
    private String testAlgorithm3 = "SHA-256";
    private int testAlgorithm3Length = 32;
    private byte[] testarray = { 3, 0, 5, 6 };
    private byte[] testarray2 = { 1, 2, 3, 4, 5, 6, 7 };

    /**
     * Test for the Different Constructors
     */
    @Test
    public void constructorTest() {
	LOGGER.info("testConstructors");
	TlsMessageDigest d = null;
	Exception e = null;
	try {
	    d = new TlsMessageDigest(DigestAlgorithm.LEGACY);
	} catch (NoSuchAlgorithmException ex) {
	    e = ex;
	    LOGGER.info("Could not Create legacy Digest");
	}
	assertNull(e);
	try {
	    d = new TlsMessageDigest(DigestAlgorithm.SHA256);
	} catch (NoSuchAlgorithmException ex) {
	    e = ex;
	    LOGGER.info("Could not Create sha256 Digest");
	}
	assertNull(e);
	try {
	    d = new TlsMessageDigest(DigestAlgorithm.SHA384);
	} catch (NoSuchAlgorithmException ex) {
	    e = ex;
	    LOGGER.info("Could not Create default sha384 Digest");
	}
	assertNull(e);
    }

    @Before
    public void setUp() {
	Exception e = null;
	try {
	    digest1 = new TlsMessageDigest(DigestAlgorithm.LEGACY);
	} catch (NoSuchAlgorithmException ex) {
	    e = ex;
	    LOGGER.info("Could not Create default Legacy Digest ");
	}
	assertNull(e);
	try {
	    digest2 = new TlsMessageDigest(DigestAlgorithm.SHA256);
	} catch (NoSuchAlgorithmException ex) {
	    e = ex;
	    LOGGER.info("Could not Create sha256 Digest");
	}
	assertNull(e);
    }

    /**
     * Test of getDigestLength method, of class TlsMessageDigest.
     */
    @Test
    public void testGetDigestLength() {
	LOGGER.info("testGetDigestLength");
	LOGGER.info("Computed Digest1:" + digest1.getDigestLength() + " Digest2:" + digest2.getDigestLength());
	assertTrue(digest1.getDigestLength() == (testAlgorithm1Length + testAlgorithm2Length));
	assertTrue(digest2.getDigestLength() == testAlgorithm3Length);

    }

    /**
     * Test of Set/Get method, of class TlsMessageDigest.
     */
    @Test
    public void testSetandGetBytes() {
	LOGGER.info("testSetAndGet");
	byte[] testarray = { 3, 0, 5, 6 };
	digest1.setRawBytes(testarray);
	assertArrayEquals(testarray, digest1.getRawBytes());
	Exception ex = null;
	try {
	    digest1.setRawBytes(null);
	} catch (Exception E) {
	    ex = E;
	}
	assertNull(ex);
    }

    /**
     * Test of update method, of class TlsMessageDigest.
     */
    @Test
    public void testUpdate() {
	LOGGER.info("testUpdate");
	digest1.setRawBytes(testarray);
	// Teste 3 methoden, überprüfe zunächst immer ob die raw bytes stimmen,
	// und danach immer ob auch intern alles richtig geupdated wuirde
	LOGGER.debug("Before:" + ArrayConverter.bytesToHexString(digest1.getRawBytes()));
	byte testbyte = 5;
	digest1.update(testbyte); // Sollte byte anhängen
	byte[] result = digest1.getRawBytes();
	LOGGER.debug("After:" + ArrayConverter.bytesToHexString(digest1.getRawBytes()));

	for (int i = 0; i < testarray.length; i++) {
	    assertTrue(result[i] == testarray[i]);
	}
	assertTrue(result[testarray.length] == testbyte);
	// Überprüfe ob nach einem Update das Digest noch identisch berechnet
	byte[] digresult = digest1.digest();
	TlsMessageDigest digestTest = null;
	try {
	    digestTest = new TlsMessageDigest(DigestAlgorithm.LEGACY);
	} catch (NoSuchAlgorithmException ex) {
	    Logger.getLogger(TlsMessageDigestTest.class.getName()).log(Level.SEVERE, null, ex);
	}
	digestTest.setRawBytes(result);
	assertArrayEquals(digestTest.digest(), digresult);
	digest1.setRawBytes(testarray);
	digest1.update(testarray2); // sollte byte Array anhängen
	result = digest1.getRawBytes();
	LOGGER.debug("After2:" + ArrayConverter.bytesToHexString(digest1.getRawBytes()));

	for (int i = 0; i < testarray.length; i++) {
	    assertTrue(result[i] == testarray[i]);
	}
	for (int i = 0; i < testarray2.length; i++) {
	    assertTrue(result[i + testarray.length] == testarray2[i]);
	}
	digresult = digest1.digest();
	digestTest = null;
	try {
	    digestTest = new TlsMessageDigest(DigestAlgorithm.LEGACY);
	} catch (NoSuchAlgorithmException ex) {
	    Logger.getLogger(TlsMessageDigestTest.class.getName()).log(Level.SEVERE, null, ex);
	}
	digestTest.setRawBytes(result);
	assertArrayEquals(digestTest.digest(), digresult);
	digest1.setRawBytes(testarray);
	int testLength = 2;
	int testPosition = 2;
	digest1.update(testarray2, testPosition, testLength);
	result = digest1.getRawBytes();

	LOGGER.debug("After3:" + ArrayConverter.bytesToHexString(digest1.getRawBytes()));

	for (int i = 0; i < testarray.length; i++) {
	    assertTrue(result[i] == testarray[i]);
	}
	for (int i = testarray.length; i < (testarray.length + testLength); i++) {
	    assertTrue(result[i] == testarray2[testPosition + i - testarray.length]);
	}
	LOGGER.debug("After3:" + ArrayConverter.bytesToHexString(digest1.getRawBytes()));
	digresult = digest1.digest();
	digestTest = null;
	try {
	    digestTest = new TlsMessageDigest(DigestAlgorithm.LEGACY);
	} catch (NoSuchAlgorithmException ex) {
	    Logger.getLogger(TlsMessageDigestTest.class.getName()).log(Level.SEVERE, null, ex);
	}
	digestTest.setRawBytes(result);
	assertArrayEquals(digestTest.digest(), digresult);
    }

    /**
     * Test of digest method, of class TlsMessageDigest.
     */
    @Test
    public void testDigest() {
	LOGGER.info("testDigest");

	digest1.setRawBytes(testarray);
	byte[] dig = digest1.digest();
	LOGGER.debug("Digest1 Lenght:" + dig.length);
	assertTrue(dig.length == (testAlgorithm1Length + testAlgorithm2Length));
	digest2.setRawBytes(testarray);
	dig = digest2.digest();
	LOGGER.debug("Digest2 Lenght:" + dig.length);
	assertTrue(dig.length == testAlgorithm3Length);
	TlsMessageDigest corruptedDigest = null;
	try {
	    corruptedDigest = new TlsMessageDigest(DigestAlgorithm.SHA256);
	    // Keine Bytes gesetzt
	    dig = corruptedDigest.digest();

	} catch (NoSuchAlgorithmException ex) {
	    ex.printStackTrace();
	}
	// testen ob das concatinieren klappt
	Exception e = null;
	try {
	    MessageDigest hash1 = MessageDigest.getInstance("MD5");
	    MessageDigest hash2 = MessageDigest.getInstance("SHA-1");
	    dig = hash1.digest();
	    byte[] dig2 = ArrayConverter.concatenate(dig, hash2.digest());
	    assertArrayEquals(dig2, digest1.digest());

	} catch (NoSuchAlgorithmException ex) {
	    e = ex;
	}
	assertTrue(e == null);
    }

    /**
     * Test of reset method, of class TlsMessageDigest.
     */
    @Test
    public void testReset() {
	LOGGER.info("testReset");
	digest1.setRawBytes(testarray);
	Exception e = null;
	TlsMessageDigest digest3 = null;
	try {
	    digest3 = new TlsMessageDigest(DigestAlgorithm.LEGACY);
	} catch (NoSuchAlgorithmException ex) {
	    e = ex;
	    LOGGER.info("Could not Create default Digest with ProtocolVersion TLS10 Constructor");
	}
	assertNull(e);
	digest1.digest();
	digest1.reset();
	digest1.setRawBytes(testarray2);
	digest3.setRawBytes(testarray2);
	assertArrayEquals(digest1.digest(), digest3.digest());

    }
}
