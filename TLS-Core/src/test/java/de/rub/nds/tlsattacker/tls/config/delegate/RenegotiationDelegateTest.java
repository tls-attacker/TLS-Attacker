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
public class RenegotiationDelegateTest {

    private RenegotiationDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public RenegotiationDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new RenegotiationDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isLegacyRenegotiation method, of class RenegotiationDelegate.
     */
    @Test
    public void testIsLegacyRenegotiation() {
        args = new String[1];
        args[0] = "-legacy_renegotiation";
        assertFalse(delegate.isLegacyRenegotiation());
        jcommander.parse(args);
        assertTrue(delegate.isLegacyRenegotiation());
    }

    /**
     * Test of setLegacyRenegotiation method, of class RenegotiationDelegate.
     */
    @Test
    public void testSetLegacyRenegotiation() {
        assertFalse(delegate.isLegacyRenegotiation());
        delegate.setLegacyRenegotiation(true);
        assertTrue(delegate.isLegacyRenegotiation());
    }

    /**
     * Test of applyDelegate method, of class RenegotiationDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = new TlsConfig();
        config.setRenegotiation(false);
        args = new String[1];
        args[0] = "-legacy_renegotiation";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isRenegotiation());
    }
}
