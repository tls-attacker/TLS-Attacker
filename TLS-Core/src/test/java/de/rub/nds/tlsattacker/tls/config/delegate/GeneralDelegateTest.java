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
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import org.apache.logging.log4j.Level;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class GeneralDelegateTest {

    private GeneralDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public GeneralDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new GeneralDelegate();
        this.jcommander = new JCommander(delegate);
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
     * Test of getLogLevel method, of class GeneralDelegate.
     */
    @Test
    public void testGetLogLevel() {
        args = new String[2];
        args[0] = "-loglevel";
        args[1] = "info";
        jcommander.parse(args);
        assertTrue(delegate.getLogLevel().equals(Level.INFO));
    }

    /**
     * Test of setLogLevel method, of class GeneralDelegate.
     */
    @Test
    public void testSetLogLevel() {
        delegate.setLogLevel(Level.FATAL);
        assertTrue(delegate.getLogLevel() == Level.FATAL);
    }

    /**
     * Test of applyDelegate method, of class GeneralDelegate.
     */
    @Test
    public void testApplyDelegate() {
        // Just check that applyDelegate does not throw an Exception
        // TODO check that loglevel gets set
        delegate.applyDelegate(new TlsConfig());
    }

}
