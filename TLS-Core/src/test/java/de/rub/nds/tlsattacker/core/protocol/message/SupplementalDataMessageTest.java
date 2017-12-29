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
 * @author Pierre Tilhaus  <pierre.tilhaus@rub.de>
 */
public class SupplementalDataMessageTest {
    
    SupplementalDataMessage message;
    
    @Before
    public void setUp() {
        message = new SupplementalDataMessage();
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of getEntries method, of class SupplementalDataMessage.
     */
    @Test
    public void testGetEntries() {
    }

    /**
     * Test of setEntries method, of class SupplementalDataMessage.
     */
    @Test
    public void testSetEntries() {
    }

    /**
     * Test of getSupplementalDataLength method, of class SupplementalDataMessage.
     */
    @Test
    public void testGetSupplementalDataLength() {
    }

    /**
     * Test of setSupplementalDataLength method, of class SupplementalDataMessage.
     */
    @Test
    public void testSetSupplementalDataLength() {
    }

    /**
     * Test of getSupplementalDataBytes method, of class SupplementalDataMessage.
     */
    @Test
    public void testGetSupplementalDataBytes() {
    }

    /**
     * Test of setSupplementalDataBytes method, of class SupplementalDataMessage.
     */
    @Test
    public void testSetSupplementalDataBytes_ModifiableByteArray() {
    }

    /**
     * Test of setSupplementalDataBytes method, of class SupplementalDataMessage.
     */
    @Test
    public void testSetSupplementalDataBytes_byteArr() {
    }

    /**
     * Test of getHandler method, of class SupplementalDataMessage.
     */
    @Test
    public void testGetHandler() {
    }

    /**
     * Test of toString method, of class SupplementalDataMessage.
     */
    @Test
    public void testToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nSupplementalDataMessage:");
        sb.append("\n  Supplemental Data Length: ").append("null");
        sb.append("\n  SupplementalDataEntries:\n").append("null");
        
        assertEquals(message.toString(), sb.toString());
    }
    
}
