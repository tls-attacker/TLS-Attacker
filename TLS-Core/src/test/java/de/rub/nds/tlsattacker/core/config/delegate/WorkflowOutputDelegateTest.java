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

public class WorkflowOutputDelegateTest {

    private WorkflowOutputDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new WorkflowOutputDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getWorkflowOutput method, of class WorkflowOutputDelegate.
     */
    @Test
    public void testGetWorkflowOutput() {
        args = new String[2];
        args[0] = "-workflow_output";
        args[1] = "path";
        assertFalse("path".equals(delegate.getWorkflowOutput()));
        jcommander.parse(args);
        assertTrue("path".equals(delegate.getWorkflowOutput()));
    }

    /**
     * Test of setWorkflowOutput method, of class WorkflowOutputDelegate.
     */
    @Test
    public void testSetWorkflowOutput() {
        assertFalse("path".equals(delegate.getWorkflowOutput()));
        delegate.setWorkflowOutput("path");
        assertTrue("path".equals(delegate.getWorkflowOutput()));
    }

    /**
     * Test of applyDelegate method, of class WorkflowOutputDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-workflow_output";
        args[1] = "path";
        jcommander.parse(args);
        assertFalse("path".equals(config.getWorkflowOutput()));
        delegate.applyDelegate(config);
        assertTrue("path".equals(config.getWorkflowOutput()));
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
