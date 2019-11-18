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
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.After;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class GeneralDelegateTest {

    private GeneralDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new GeneralDelegate();
        this.jcommander = new JCommander(delegate);
    }

    @After
    public void tearDown() {
        this.delegate.setDebug(false);
        delegate.applyDelegate(Config.createConfig());
    }

    /**
     * Test of isHelp method, of class GeneralDelegate.
     */
    @Test
    public void testIsHelp() {
        args = new String[1];
        args[0] = "-help";
        assertFalse(delegate.isHelp());
        jcommander.parse(args);
        assertTrue(delegate.isHelp());
        delegate = new GeneralDelegate();
        args[0] = "-h";
        jcommander = new JCommander(delegate);
        jcommander.parse(args);
        assertTrue(delegate.isHelp());

    }

    /**
     * Test of setHelp method, of class GeneralDelegate.
     */
    @Test
    public void testSetHelp() {
        assertFalse(delegate.isHelp());
        delegate.setHelp(true);
        assertTrue(delegate.isHelp());
    }

    /**
     * Test of isDebug method, of class GeneralDelegate.
     */
    @Test
    public void testIsDebug() {
        args = new String[1];
        args[0] = "-debug";
        assertFalse(delegate.isDebug());
        jcommander.parse(args);
        assertTrue(delegate.isDebug());
    }

    /**
     * Test of setDebug method, of class GeneralDelegate.
     */
    @Test
    public void testSetDebug() {
        assertFalse(delegate.isDebug());
        delegate.setDebug(true);
        assertTrue(delegate.isDebug());
    }

    /**
     * Test of isQuiet method, of class GeneralDelegate.
     */
    @Test
    public void testIsQuiet() {
        args = new String[1];
        args[0] = "-quiet";
        assertFalse(delegate.isQuiet());
        jcommander.parse(args);
        assertTrue(delegate.isQuiet());
    }

    /**
     * Test of setQuiet method, of class GeneralDelegate.
     */
    @Test
    public void testSetQuiet() {
        assertFalse(delegate.isQuiet());
        delegate.setQuiet(true);
        assertTrue(delegate.isQuiet());
    }

    /**
     * Test of applyDelegate method, of class GeneralDelegate.
     */
    @Test
    public void testApplyDelegate() {
        // Just check that applyDelegate does not throw an Exception
        // TODO check that loglevel gets set
        delegate.applyDelegate(Config.createConfig());
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
