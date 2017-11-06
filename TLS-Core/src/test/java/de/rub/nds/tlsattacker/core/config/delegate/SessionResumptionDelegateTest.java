/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class SessionResumptionDelegateTest {

    private SessionResumptionDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new SessionResumptionDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getSessionId method, of class SessionResumptionDelegate.
     */
    @Test
    public void testGetSessionID() {
        args = new String[2];
        args[0] = "-session_id";
        args[1] = "00112233445566778899AABBCCDDEEFF";
        delegate.setSessionId(null);
        jcommander.parse(args);
        byte[] expected = { (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66,
                (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE,
                (byte) 0xFF };
        assertArrayEquals(delegate.getSessionId(), expected);
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
        delegate.setSessionId(expected);
        assertArrayEquals(delegate.getSessionId(), expected);
    }

    /**
     * Test of applyDelegate method, of class SessionResumptionDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-session_id";
        args[1] = "00112233445566778899AABBCCDDEEFF";
        delegate.setSessionId(null);
        jcommander.parse(args);
        delegate.applyDelegate(config);
        byte[] expected = { (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66,
                (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE,
                (byte) 0xFF };
        assertArrayEquals(config.getDefaultClientSessionId(), expected);
        assertArrayEquals(config.getDefaultServerSessionId(), expected);

    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }
}
