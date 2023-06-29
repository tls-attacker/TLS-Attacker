/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import static org.junit.jupiter.api.Assertions.*;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class GeneralDelegateTest extends AbstractDelegateTest<GeneralDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new GeneralDelegate());
    }

    /** Test of isHelp method, of class GeneralDelegate. */
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

    /** Test of setHelp method, of class GeneralDelegate. */
    @Test
    public void testSetHelp() {
        assertFalse(delegate.isHelp());
        delegate.setHelp(true);
        assertTrue(delegate.isHelp());
    }

    /** Test of isDebug method, of class GeneralDelegate. */
    @Test
    public void testIsDebug() {
        args = new String[1];
        args[0] = "-debug";
        assertFalse(delegate.isDebug());
        jcommander.parse(args);
        assertTrue(delegate.isDebug());
    }

    /** Test of setDebug method, of class GeneralDelegate. */
    @Test
    public void testSetDebug() {
        assertFalse(delegate.isDebug());
        delegate.setDebug(true);
        assertTrue(delegate.isDebug());
    }

    /** Test of isQuiet method, of class GeneralDelegate. */
    @Test
    public void testIsQuiet() {
        args = new String[1];
        args[0] = "-quiet";
        assertFalse(delegate.isQuiet());
        jcommander.parse(args);
        assertTrue(delegate.isQuiet());
    }

    /** Test of setQuiet method, of class GeneralDelegate. */
    @Test
    public void testSetQuiet() {
        assertFalse(delegate.isQuiet());
        delegate.setQuiet(true);
        assertTrue(delegate.isQuiet());
    }

    /** Test of getKeylogfile method, of class GeneralDelegate. */
    @Test
    public void testIsKeylogfile() {
        args = new String[2];
        args[0] = "-keylogfile";
        args[1] = "abc";
        assertNull(delegate.getKeylogfile());
        jcommander.parse(args);
        assertEquals("abc", delegate.getKeylogfile());
    }

    /** Test of setKeylogfile method, of class GeneralDelegate. */
    @Test
    public void testSetKeylogfile() {
        assertNull(delegate.getKeylogfile());
        delegate.setKeylogfile("abc");
        assertEquals("abc", delegate.getKeylogfile());
    }

    /** Test of applyDelegate method, of class GeneralDelegate. */
    @Test
    public void testApplyDelegate() {
        // Just check that applyDelegate does not throw an Exception
        // TODO check that logLevel gets set
        Config config = Config.createConfig();
        delegate.setKeylogfile("abc");
        delegate.applyDelegate(config);
        assertTrue(config.isWriteKeylogFile());
        assertEquals("abc", config.getKeylogFilePath());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));
    }
}
