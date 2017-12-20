/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Pierre Tilhaus <pierre.tilhaus@rub.de>
 */
public class SSL2ServerHelloMessageTest {

    SSL2ServerHelloMessage message;

    @Before
    public void setUp() {
        message = new SSL2ServerHelloMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toCompactString method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of getHandler method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of getMessageLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetMessageLength() {
    }

    /**
     * Test of setMessageLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetMessageLength_ModifiableInteger() {
    }

    /**
     * Test of setMessageLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetMessageLength_int() {
    }

    /**
     * Test of getType method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetType() {
    }

    /**
     * Test of setType method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetType_ModifiableByte() {
    }

    /**
     * Test of setType method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetType_byte() {
    }

    /**
     * Test of getSessionIdHit method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetSessionIdHit() {
    }

    /**
     * Test of setSessionIdHit method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetSessionIdHit_ModifiableByte() {
    }

    /**
     * Test of setSessionIdHit method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetSessionIdHit_byte() {
    }

    /**
     * Test of getCertificateType method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetCertificateType() {
    }

    /**
     * Test of setCertificateType method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCertificateType_ModifiableByte() {
    }

    /**
     * Test of setCertificateType method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCertificateType_byte() {
    }

    /**
     * Test of getProtocolVersion method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetProtocolVersion() {
    }

    /**
     * Test of setProtocolVersion method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetProtocolVersion_ModifiableByteArray() {
    }

    /**
     * Test of setProtocolVersion method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetProtocolVersion_byteArr() {
    }

    /**
     * Test of getCertificateLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetCertificateLength() {
    }

    /**
     * Test of setCertificateLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCertificateLength_int() {
    }

    /**
     * Test of setCertificateLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCertificateLength_ModifiableInteger() {
    }

    /**
     * Test of getCipherSuitesLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetCipherSuitesLength() {
    }

    /**
     * Test of setCipherSuitesLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCipherSuitesLength_ModifiableInteger() {
    }

    /**
     * Test of setCipherSuitesLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCipherSuitesLength_int() {
    }

    /**
     * Test of getSessionIdLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetSessionIdLength() {
    }

    /**
     * Test of setSessionIdLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetSessionIdLength() {
    }

    /**
     * Test of setSessionIDLength method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetSessionIDLength() {
    }

    /**
     * Test of getCertificate method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetCertificate() {
    }

    /**
     * Test of setCertificate method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCertificate_ModifiableByteArray() {
    }

    /**
     * Test of setCertificate method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCertificate_byteArr() {
    }

    /**
     * Test of getCipherSuites method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetCipherSuites() {
    }

    /**
     * Test of setCipherSuites method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCipherSuites_ModifiableByteArray() {
    }

    /**
     * Test of setCipherSuites method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetCipherSuites_byteArr() {
    }

    /**
     * Test of getSessionId method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testGetSessionId() {
    }

    /**
     * Test of setSessionId method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetSessionId() {
    }

    /**
     * Test of setSessionID method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testSetSessionID() {
    }

    /**
     * Test of toString method, of class SSL2ServerHelloMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SSL2ServerHelloMessage:");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Type: ").append("null");
        sb.append("\n  Supported CipherSuites: ").append("null");
        sb.append("\n  SessionIdHit: ").append("null");
        sb.append("\n  Certificate: ").append("null");
        sb.append("\n  SessionID: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
