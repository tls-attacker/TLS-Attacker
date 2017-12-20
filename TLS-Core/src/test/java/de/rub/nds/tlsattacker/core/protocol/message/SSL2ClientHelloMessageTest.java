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
public class SSL2ClientHelloMessageTest {

    SSL2ClientHelloMessage message;

    @Before
    public void setUp() {
        message = new SSL2ClientHelloMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of toCompactString method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testToCompactString() {
    }

    /**
     * Test of getHandler method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of getMessageLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetMessageLength() {
    }

    /**
     * Test of setMessageLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetMessageLength_ModifiableInteger() {
    }

    /**
     * Test of setMessageLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetMessageLength_Integer() {
    }

    /**
     * Test of getType method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetType() {
    }

    /**
     * Test of setType method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetType_ModifiableByte() {
    }

    /**
     * Test of setType method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetType_byte() {
    }

    /**
     * Test of getProtocolVersion method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetProtocolVersion() {
    }

    /**
     * Test of setProtocolVersion method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetProtocolVersion_ModifiableByteArray() {
    }

    /**
     * Test of setProtocolVersion method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetProtocolVersion_byteArr() {
    }

    /**
     * Test of getCipherSuiteLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetCipherSuiteLength() {
    }

    /**
     * Test of setCipherSuiteLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetCipherSuiteLength_ModifiableInteger() {
    }

    /**
     * Test of setCipherSuiteLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetCipherSuiteLength_int() {
    }

    /**
     * Test of getCipherSuites method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetCipherSuites() {
    }

    /**
     * Test of setCipherSuites method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetCipherSuites_ModifiableByteArray() {
    }

    /**
     * Test of setCipherSuites method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetCipherSuites_byteArr() {
    }

    /**
     * Test of getChallenge method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetChallenge() {
    }

    /**
     * Test of setChallenge method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetChallenge_ModifiableByteArray() {
    }

    /**
     * Test of setChallenge method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetChallenge_byteArr() {
    }

    /**
     * Test of getSessionIdLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetSessionIdLength() {
    }

    /**
     * Test of setSessionIdLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetSessionIdLength() {
    }

    /**
     * Test of setSessionIDLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetSessionIDLength() {
    }

    /**
     * Test of getChallengeLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetChallengeLength() {
    }

    /**
     * Test of setChallengeLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetChallengeLength_int() {
    }

    /**
     * Test of setChallengeLength method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetChallengeLength_ModifiableInteger() {
    }

    /**
     * Test of getSessionId method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testGetSessionId() {
    }

    /**
     * Test of setSessionId method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetSessionId() {
    }

    /**
     * Test of setSessionID method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testSetSessionID() {
    }

    /**
     * Test of toString method, of class SSL2ClientHelloMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("SSL2ClientHelloMessage:");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Type: ").append("null");
        sb.append("\n  Supported CipherSuites: ").append("null");
        sb.append("\n  Challange: ").append("null");
        sb.append("\n  SessionID: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

}
