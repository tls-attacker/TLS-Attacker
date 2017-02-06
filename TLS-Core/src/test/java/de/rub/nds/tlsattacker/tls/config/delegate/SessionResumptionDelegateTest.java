/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.config.delegate;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SessionResumptionDelegateTest {

    private SessionResumptionDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public SessionResumptionDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new SessionResumptionDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isSessionResumption method, of class SessionResumptionDelegate.
     */
    @Test
    public void testIsSessionResumption() {
        args = new String[1];
        args[0] = "-session_resumption";
        assertFalse(delegate.isSessionResumption());
        jcommander.parse(args);
        assertTrue(delegate.isSessionResumption());
    }

    /**
     * Test of setSessionResumption method, of class SessionResumptionDelegate.
     */
    @Test
    public void testSetSessionResumption() {
        assertFalse(delegate.isSessionResumption());
        delegate.setSessionResumption(true);
        assertTrue(delegate.isSessionResumption());
    }

    /**
     * Test of getSessionID method, of class SessionResumptionDelegate.
     */
    @Test
    public void testGetSessionID() {
        args = new String[2];
        args[0] = "-session_id";
        args[1] = "00112233445566778899AABBCCDDEEFF";
        delegate.setSessionID(null);
        jcommander.parse(args);
        byte[] expected = { (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66,
                (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE,
                (byte) 0xFF };
        assertArrayEquals(delegate.getSessionID(), expected);
    }

    @Test(expected = ParameterException.class)
    public void testGetInvalidSessionId() {
        args = new String[2];
        args[0] = "-session_id";
        args[1] = "NOTAHEXSTRING";
        jcommander.parse(args);
    }

    /**
     * Test of setSessionID method, of class SessionResumptionDelegate.
     */
    @Test
    public void testSetSessionID() {
        byte[] expected = { (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66,
                (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE,
                (byte) 0xFF };
        delegate.setSessionID(expected);
        assertArrayEquals(delegate.getSessionID(), expected);
    }

    /**
     * Test of applyDelegate method, of class SessionResumptionDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = new TlsConfig();
        args = new String[3];
        args[0] = "-session_id";
        args[1] = "00112233445566778899AABBCCDDEEFF";
        args[2] = "-session_resumption";
        delegate.setSessionID(null);
        jcommander.parse(args);
        delegate.applyDelegate(config);
        byte[] expected = { (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66,
                (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE,
                (byte) 0xFF };
        assertArrayEquals(config.getSessionId(), expected);
        assertTrue(config.isSessionResumption());
    }

}
