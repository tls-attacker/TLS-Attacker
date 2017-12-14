/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import javax.xml.ws.Service;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Pierre Tilhaus
 */
public class CertificateVerifyMessageTest {

    CertificateVerifyMessage message;

    @Before
    public void setUp() {
        message = new CertificateVerifyMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getSignatureHashAlgorithm method, of class
     * CertificateVerifyMessage.
     */
    @Test
    public void testGetSignatureHashAlgorithm() {
    }

    /**
     * Test of setSignatureHashAlgorithm method, of class
     * CertificateVerifyMessage.
     */
    @Test
    public void testSetSignatureHashAlgorithm_ModifiableByteArray() {
    }

    /**
     * Test of setSignatureHashAlgorithm method, of class
     * CertificateVerifyMessage.
     */
    @Test
    public void testSetSignatureHashAlgorithm_byteArr() {
    }

    /**
     * Test of getSignatureLength method, of class CertificateVerifyMessage.
     */
    @Test
    public void testGetSignatureLength() {
    }

    /**
     * Test of setSignatureLength method, of class CertificateVerifyMessage.
     */
    @Test
    public void testSetSignatureLength_ModifiableInteger() {
    }

    /**
     * Test of setSignatureLength method, of class CertificateVerifyMessage.
     */
    @Test
    public void testSetSignatureLength_int() {
    }

    /**
     * Test of getSignature method, of class CertificateVerifyMessage.
     */
    @Test
    public void testGetSignature() {
    }

    /**
     * Test of setSignature method, of class CertificateVerifyMessage.
     */
    @Test
    public void testSetSignature_ModifiableByteArray() {
    }

    /**
     * Test of setSignature method, of class CertificateVerifyMessage.
     */
    @Test
    public void testSetSignature_byteArr() {
    }

    /**
     * Test of toString method, of class CertificateVerifyMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("CertificateVerifyMessage:").append("\n  SignatureAndHashAlgorithm: ").append("null")
                .append("\n  Signature Length: ").append("null").append("\n  Signature: ").append("null");
        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getHandler method, of class CertificateVerifyMessage.
     */
    @Test
    public void testGetHandler() {
    }

}
