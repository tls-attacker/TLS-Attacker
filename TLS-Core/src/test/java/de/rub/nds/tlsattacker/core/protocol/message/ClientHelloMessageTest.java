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
 * @author Pierre Tilhaus
 */
public class ClientHelloMessageTest {

    ClientHelloMessage message;

    @Before
    public void setUp() {
        message = new ClientHelloMessage();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getCompressionLength method, of class ClientHelloMessage.
     */
    @Test
    public void testGetCompressionLength() {
    }

    /**
     * Test of getCipherSuiteLength method, of class ClientHelloMessage.
     */
    @Test
    public void testGetCipherSuiteLength() {
    }

    /**
     * Test of getCipherSuites method, of class ClientHelloMessage.
     */
    @Test
    public void testGetCipherSuites() {
    }

    /**
     * Test of getCompressions method, of class ClientHelloMessage.
     */
    @Test
    public void testGetCompressions() {
    }

    /**
     * Test of setCompressionLength method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCompressionLength_ModifiableInteger() {
    }

    /**
     * Test of setCipherSuiteLength method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCipherSuiteLength_ModifiableInteger() {
    }

    /**
     * Test of setCipherSuites method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCipherSuites_ModifiableByteArray() {
    }

    /**
     * Test of setCompressions method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCompressions_ModifiableByteArray() {
    }

    /**
     * Test of setCompressionLength method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCompressionLength_int() {
    }

    /**
     * Test of setCipherSuiteLength method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCipherSuiteLength_int() {
    }

    /**
     * Test of setCipherSuites method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCipherSuites_byteArr() {
    }

    /**
     * Test of setCompressions method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCompressions_byteArr() {
    }

    /**
     * Test of getCookie method, of class ClientHelloMessage.
     */
    @Test
    public void testGetCookie() {
    }

    /**
     * Test of getCookieLength method, of class ClientHelloMessage.
     */
    @Test
    public void testGetCookieLength() {
    }

    /**
     * Test of setCookie method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCookie_byteArr() {
    }

    /**
     * Test of setCookie method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCookie_ModifiableByteArray() {
    }

    /**
     * Test of setCookieLength method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCookieLength_byte() {
    }

    /**
     * Test of setCookieLength method, of class ClientHelloMessage.
     */
    @Test
    public void testSetCookieLength_ModifiableByte() {
    }

    /**
     * Test of toString method, of class ClientHelloMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nClientHelloMessage:");
        sb.append("\n  Protocol Version: ").append("null");
        sb.append("\n  Client Unix Time: ").append("null");
        sb.append("\n  Client Random: ").append("null");
        sb.append("\n  Session ID: ").append("null");
        sb.append("\n  Supported Cipher Suites: ").append("null");
        sb.append("\n  Supported Compression Methods: ").append("null");
        sb.append("\n  Extensions: ").append("null");

        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getHandler method, of class ClientHelloMessage.
     */
    @Test
    public void testGetHandler() {
    }

}
