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
public class HelloVerifyRequestMessageTest {
    
   HelloVerifyRequestMessage message;
    
    @Before
    public void setUp() {
        message = new HelloVerifyRequestMessage();
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of getProtocolVersion method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testGetProtocolVersion() {
    }

    /**
     * Test of getCookie method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testGetCookie() {
    }

    /**
     * Test of getCookieLength method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testGetCookieLength() {
    }

    /**
     * Test of setProtocolVersion method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testSetProtocolVersion_byteArr() {
    }

    /**
     * Test of setProtocolVersion method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testSetProtocolVersion_ModifiableByteArray() {
    }

    /**
     * Test of setCookie method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testSetCookie_byteArr() {
    }

    /**
     * Test of setCookie method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testSetCookie_ModifiableByteArray() {
    }

    /**
     * Test of setCookieLength method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testSetCookieLength_byte() {
    }

    /**
     * Test of setCookieLength method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testSetCookieLength_ModifiableByte() {
    }

    /**
     * Test of getHandler method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toString method, of class HelloVerifyRequestMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nHelloVerifyRequestMessage:");
        sb.append("\n  ProtocolVersion: ").append("null");
        sb.append("\n  Cookie Length: ").append("null");
        sb.append("\n  Cookie: ").append("null");
        
        assertEquals(message.toString(), sb.toString());
    }
    
}
