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
public class DynamicWorkflowDelegateTest {

    private DynamicWorkflowDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public DynamicWorkflowDelegateTest() {
    }

    @Before
    public void setUp() {
        this.delegate = new DynamicWorkflowDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of isDynamicWorkflow method, of class DynamicWorkflowDelegate.
     */
    @Test
    public void testIsDynamicWorkflow() {
        args = new String[1];
        args[0] = "-dynamic_workflow";
        assertFalse(delegate.isDynamicWorkflow());
        jcommander.parse(args);
        assertTrue(delegate.isDynamicWorkflow());
    }

    /**
     * Test of setDynamicWorkflow method, of class DynamicWorkflowDelegate.
     */
    @Test
    public void testSetDynamicWorkflow() {
        assertFalse(delegate.isDynamicWorkflow());
        delegate.setDynamicWorkflow(true);
        assertTrue(delegate.isDynamicWorkflow());
    }

    /**
     * Test of applyDelegate method, of class DynamicWorkflowDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = new TlsConfig();
        config.setDynamicWorkflow(false);
        args = new String[1];
        args[0] = "-dynamic_workflow";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isDynamicWorkflow());
    }
}
