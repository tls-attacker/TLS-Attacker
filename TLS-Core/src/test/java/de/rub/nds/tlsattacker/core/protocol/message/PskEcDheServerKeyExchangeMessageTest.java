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
public class PskEcDheServerKeyExchangeMessageTest {
    
    PskEcDheServerKeyExchangeMessage message;
    
    @Before
    public void setUp() {
        message = new PskEcDheServerKeyExchangeMessage();
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of getIdentityHint method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testGetIdentityHint() {
    }

    /**
     * Test of setIdentityHint method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityHint_ModifiableByteArray() {
    }

    /**
     * Test of setIdentityHint method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityHint_byteArr() {
    }

    /**
     * Test of getIdentityHintLength method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testGetIdentityHintLength() {
    }

    /**
     * Test of setIdentityHintLength method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityHintLength_ModifiableInteger() {
    }

    /**
     * Test of setIdentityHintLength method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testSetIdentityHintLength_int() {
    }

    /**
     * Test of toString method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nPskEcDheServerKeyExchangeMessage:");
        sb.append("\n  Curve Type: ").append("null");
        sb.append("\n  Named Curve: ").append("null");
        sb.append("\n  Public Key: ").append("null");
        
        assertEquals(message.toString(), sb.toString());
    }

    /**
     * Test of getHandler method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toCompactString method, of class PskEcDheServerKeyExchangeMessage.
     */
    @Test
    public void testToCompactString() {
    }
    
}
