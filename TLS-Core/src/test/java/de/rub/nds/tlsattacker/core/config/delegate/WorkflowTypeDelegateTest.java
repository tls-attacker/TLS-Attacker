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
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class WorkflowTypeDelegateTest {

    private WorkflowTypeDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        this.delegate = new WorkflowTypeDelegate();
        this.jcommander = new JCommander(delegate);
    }

    /**
     * Test of getWorkflowTraceType method, of class WorkflowTypeDelegate.
     */
    @Test
    public void testGetWorkflowTraceType() {
        args = new String[2];
        args[0] = "-workflow_trace_type";
        args[1] = "HANDSHAKE";
        assertFalse(WorkflowTraceType.HANDSHAKE.equals(delegate.getWorkflowTraceType()));
        jcommander.parse(args);
        assertTrue(delegate.getWorkflowTraceType().equals(WorkflowTraceType.HANDSHAKE));
    }

    /**
     * Test of setWorkflowTraceType method, of class WorkflowTypeDelegate.
     */
    @Test
    public void testSetWorkflowTraceType() {
        assertFalse(WorkflowTraceType.HANDSHAKE.equals(delegate.getWorkflowTraceType()));
        delegate.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        assertTrue(delegate.getWorkflowTraceType().equals(WorkflowTraceType.HANDSHAKE));
    }

    /**
     * Test of applyDelegate method, of class WorkflowTypeDelegate.
     */
    @Test
    public void testApplyDelegate() {
        Config config = Config.createConfig();
        args = new String[2];
        args[0] = "-workflow_trace_type";
        args[1] = "FULL";
        jcommander.parse(args);
        assertFalse(WorkflowTraceType.FULL.equals(config.getWorkflowTraceType()));
        delegate.applyDelegate(config);
        assertTrue(WorkflowTraceType.FULL.equals(config.getWorkflowTraceType()));
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
