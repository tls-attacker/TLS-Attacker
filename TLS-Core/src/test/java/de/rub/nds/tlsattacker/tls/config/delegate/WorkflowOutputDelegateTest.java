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
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowOutputDelegateTest {

    private WorkflowOutputDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public WorkflowOutputDelegateTest() {

    }

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
        TlsConfig config = TlsConfig.createConfig();
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
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
                                                                                // ugly
    }
}
