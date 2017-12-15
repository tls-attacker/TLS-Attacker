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
public class PskEcDhClientKeyExchangeMessageTest {
    
    PskEcDhClientKeyExchangeMessage message;
    
    @Before
    public void setUp() {
        message = new PskEcDhClientKeyExchangeMessage();
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of toString method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nPskEcDhClientKeyExchangeMessage:");
        sb.append("\n  PSKIdentity Length: ").append("null");
        sb.append("\n  PSKIdentity: ").append("null");
        
        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getIdentity method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testGetIdentity() {
    }

    /**
     * Test of setIdentity method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testSetIdentity_ModifiableByteArray() {
    }

    /**
     * Test of setIdentity method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testSetIdentity_byteArr() {
    }

    /**
     * Test of getIdentityLength method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testGetIdentityLength() {
    }

    /**
     * Test of setIdentityLength method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityLength_ModifiableInteger() {
    }

    /**
     * Test of setIdentityLength method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityLength_Integer() {
    }

    /**
     * Test of getHandler method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toCompactString method, of class PskEcDhClientKeyExchangeMessage.
     */
    @Test
    public void testToCompactString() {
    }
    
}
