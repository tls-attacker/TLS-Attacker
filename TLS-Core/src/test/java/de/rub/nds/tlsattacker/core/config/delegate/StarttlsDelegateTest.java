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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class StarttlsDelegateTest {
    private StarttlsDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public StarttlsDelegateTest() {
    }

    @Before
    public void setUp() {
        delegate = new StarttlsDelegate();
        jcommander = new JCommander(delegate);
    }

    /**
     * Test of getStarttlsType method, of class StarttlsDelegate.
     */
    @Test
    public void testGetStarttlsType() {
        args = new String[2];
        args[0] = "-starttls";
        args[1] = "POP3";
        delegate.setStarttlsType(null);
        assertFalse(delegate.getStarttlsType() == StarttlsType.NONE);
        jcommander.parse(args);
        assertTrue(delegate.getStarttlsType() == StarttlsType.POP3);
    }

    /**
     * Test of setStarttlsType method, of class StarttlsDelegate.
     */
    @Test
    public void testSetStarttlsType() {
        assertTrue(delegate.getStarttlsType() == StarttlsType.NONE);
        delegate.setStarttlsType(StarttlsType.POP3);
        assertTrue(delegate.getStarttlsType() == StarttlsType.POP3);
    }

    /**
     * Test of applyDelegate method, of class StarttlsDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-starttls";
        args[1] = "POP3";

        jcommander.parse(args);
        delegate.applyDelegate(config);

        assertTrue(config.getStarttlsType() == StarttlsType.POP3);
    }

}
