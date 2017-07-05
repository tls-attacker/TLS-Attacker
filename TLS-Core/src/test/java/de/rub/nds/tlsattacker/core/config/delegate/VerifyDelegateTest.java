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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class VerifyDelegateTest {

    private VerifyDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new VerifyDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isVerifyWorkflowCorrectness method, of class VerifyDelegate.
     */
    @Test
    public void testIsVerifyWorkflowCorrectness() {
        args = new String[1];
        args[0] = "-verify_workflow_correctness";
        assertTrue(delegate.isVerifyWorkflowCorrectness() == null);
        jcommander.parse(args);
        assertTrue(delegate.isVerifyWorkflowCorrectness());
    }

    /**
     * Test of setVerifyWorkflowCorrectness method, of class VerifyDelegate.
     */
    @Test
    public void testSetVerifyWorkflowCorrectness() {
        assertTrue(delegate.isVerifyWorkflowCorrectness() == null);
        delegate.setVerifyWorkflowCorrectness(true);
        assertTrue(delegate.isVerifyWorkflowCorrectness());
    }

    /**
     * Test of applyDelegate method, of class VerifyDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[1];
        args[0] = "-verify_workflow_correctness";
        jcommander.parse(args);
        config.setVerifyWorkflow(false);
        assertFalse(config.isVerifyWorkflow());
        delegate.applyDelegate(config);
        assertTrue(config.isVerifyWorkflow());
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
