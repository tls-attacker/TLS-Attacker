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
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowTypeDelegateTest {

    private WorkflowTypeDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    public WorkflowTypeDelegateTest() {
    }

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
        TlsConfig config = new TlsConfig();
        args = new String[2];
        args[0] = "-workflow_trace_type";
        args[1] = "HANDSHAKE";
        jcommander.parse(args);
        assertFalse(WorkflowTraceType.HANDSHAKE.equals(config.getWorkflowTraceType()));
        delegate.applyDelegate(config);
        assertTrue(WorkflowTraceType.HANDSHAKE.equals(config.getWorkflowTraceType()));
    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = new TlsConfig();
        TlsConfig config2 = new TlsConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore"));// little
                                                                                // ugly
    }
}
