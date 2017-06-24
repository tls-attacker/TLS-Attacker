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
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzingModeDelegateTest {

    private FuzzingModeDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new FuzzingModeDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isFuzzingMode method, of class FuzzingModeDelegate.
     */
    @Test
    public void testIsFuzzingMode() {
        args = new String[1];
        args[0] = "-fuzzing";
        assertTrue(delegate.isFuzzingMode() == null);
        jcommander.parse(args);
        assertTrue(delegate.isFuzzingMode());
    }

    /**
     * Test of setFuzzingMode method, of class FuzzingModeDelegate.
     */
    @Test
    public void testSetFuzzingMode() {
        assertTrue(delegate.isFuzzingMode() == null);
        delegate.setFuzzingMode(true);
        assertTrue(delegate.isFuzzingMode());
    }

    /**
     * Test of applyDelegate method, of class FuzzingModeDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = TlsConfig.createConfig();
        config.setFuzzingMode(false);
        args = new String[1];
        args[0] = "-fuzzing";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isFuzzingMode());
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }
}
