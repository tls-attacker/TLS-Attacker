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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class WorkflowTypeDelegateTest extends AbstractDelegateTest<WorkflowTypeDelegate> {

    @BeforeEach
    public void setUp() {
        super.setUp(new WorkflowTypeDelegate());
    }

    /** Test of getWorkflowTraceType method, of class WorkflowTypeDelegate. */
    @Test
    public void testGetWorkflowTraceType() {
        args = new String[2];
        args[0] = "-workflow_trace_type";
        args[1] = "HANDSHAKE";
        assertNotEquals(WorkflowTraceType.HANDSHAKE, delegate.getWorkflowTraceType());
        jcommander.parse(args);
        assertEquals(WorkflowTraceType.HANDSHAKE, delegate.getWorkflowTraceType());
    }

    /** Test of setWorkflowTraceType method, of class WorkflowTypeDelegate. */
    @Test
    public void testSetWorkflowTraceType() {
        assertNotEquals(WorkflowTraceType.HANDSHAKE, delegate.getWorkflowTraceType());
        delegate.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        assertEquals(WorkflowTraceType.HANDSHAKE, delegate.getWorkflowTraceType());
    }

    /** Test of applyDelegate method, of class WorkflowTypeDelegate. */
    @Test
    public void testApplyDelegate() {
        Config config = new Config();
        args = new String[2];
        args[0] = "-workflow_trace_type";
        args[1] = "FULL";
        jcommander.parse(args);
        assertNotEquals(WorkflowTraceType.FULL, config.getWorkflowTraceType());
        delegate.applyDelegate(config);
        assertEquals(WorkflowTraceType.FULL, config.getWorkflowTraceType());
    }

    @Test
    public void testNothingSetNothingChanges() {
        Config config = new Config();
        Config config2 = new Config();
        delegate.applyDelegate(config);
        assertTrue(
                EqualsBuilder.reflectionEquals(
                        config, config2, "certificateChainConfig")); // little
        // ugly
    }

    @Test
    public void testApplyDelegateHttps() {
        Config config = new Config();
        args = new String[2];
        args[0] = "-workflow_trace_type";
        args[1] = "HTTPS";
        jcommander.parse(args);

        // Default should be TLS
        assertEquals(StackConfiguration.TLS, config.getDefaultLayerConfiguration());

        delegate.applyDelegate(config);

        // Should be HTTPS after applying delegate
        assertEquals(WorkflowTraceType.HTTPS, config.getWorkflowTraceType());
        assertEquals(StackConfiguration.HTTPS, config.getDefaultLayerConfiguration());
    }

    @Test
    public void testApplyDelegateDynamicHttps() {
        Config config = new Config();
        args = new String[2];
        args[0] = "-workflow_trace_type";
        args[1] = "DYNAMIC_HTTPS";
        jcommander.parse(args);

        // Default should be TLS
        assertEquals(StackConfiguration.TLS, config.getDefaultLayerConfiguration());

        delegate.applyDelegate(config);

        // Should be HTTPS after applying delegate
        assertEquals(WorkflowTraceType.DYNAMIC_HTTPS, config.getWorkflowTraceType());
        assertEquals(StackConfiguration.HTTPS, config.getDefaultLayerConfiguration());
    }

    @Test
    public void testApplyDelegateNonHttpsWorkflow() {
        Config config = new Config();
        args = new String[2];
        args[0] = "-workflow_trace_type";
        args[1] = "HANDSHAKE";
        jcommander.parse(args);

        // Default should be TLS
        assertEquals(StackConfiguration.TLS, config.getDefaultLayerConfiguration());

        delegate.applyDelegate(config);

        // Should remain TLS for non-HTTPS workflows
        assertEquals(WorkflowTraceType.HANDSHAKE, config.getWorkflowTraceType());
        assertEquals(StackConfiguration.TLS, config.getDefaultLayerConfiguration());
    }
}
