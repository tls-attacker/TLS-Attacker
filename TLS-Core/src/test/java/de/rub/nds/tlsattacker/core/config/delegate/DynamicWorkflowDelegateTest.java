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
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class DynamicWorkflowDelegateTest {

    private DynamicWorkflowDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new DynamicWorkflowDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isDynamicWorkflow method, of class DynamicWorkflowDelegate.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testIsDynamicWorkflow() {
        args = new String[1];
        args[0] = "-dynamic_workflow";
        assertTrue(delegate.isDynamicWorkflow() == null);
        jcommander.parse(args);
        assertTrue(delegate.isDynamicWorkflow());
    }

    /**
     * Test of setDynamicWorkflow method, of class DynamicWorkflowDelegate.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testSetDynamicWorkflow() {
        assertTrue(delegate.isDynamicWorkflow() == null);
        delegate.setDynamicWorkflow(true);
        assertTrue(delegate.isDynamicWorkflow());
    }

    /**
     * Test of applyDelegate method, of class DynamicWorkflowDelegate.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        config.setDynamicWorkflow(false);
        args = new String[1];
        args[0] = "-dynamic_workflow";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isDynamicWorkflow());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testNothingSetNothingChanges() {
        Config config = Config.createConfig();
        Config config2 = Config.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }
}
