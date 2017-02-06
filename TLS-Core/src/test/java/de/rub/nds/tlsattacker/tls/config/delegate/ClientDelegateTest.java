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
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientDelegateTest {

    private ClientDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public ClientDelegateTest() {
    }

    @Before
    public void setUp() {
        delegate = new ClientDelegate();
        jcommander = new JCommander(delegate);
    }

    /**
     * Test of getHost method, of class ClientDelegate.
     */
    @Test
    public void testGetHost() {
        args = new String[2];
        args[0] = "-connect";
        args[1] = "127.0.1.1";
        assertFalse(delegate.getHost().equals("127.0.1.1"));
        jcommander.parse(args);
        assertTrue(delegate.getHost().equals("127.0.1.1"));
    }

    /**
     * Test of setHost method, of class ClientDelegate.
     */
    @Test
    public void testSetHost() {
        assertFalse(delegate.getHost().equals("123456"));
        delegate.setHost("123456");
        assertTrue(delegate.getHost().equals("123456"));
    }

    /**
     * Test of applyDelegate method, of class ClientDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = new TlsConfig();
        config.setHost(null);
        args = new String[2];
        args[0] = "-connect";
        args[1] = "123456";

        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.getHost().equals("123456"));
    }

}
