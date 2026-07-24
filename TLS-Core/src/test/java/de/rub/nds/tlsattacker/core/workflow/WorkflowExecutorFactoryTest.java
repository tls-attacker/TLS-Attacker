/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import org.junit.jupiter.api.Test;

public class WorkflowExecutorFactoryTest {

    @Test
    public void testCreateDefaultExecutor() {
        Config config = new Config();
        State state = new State(config);
        WorkflowExecutor executor =
                WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
        assertNotNull(executor);
        assertTrue(executor instanceof DefaultWorkflowExecutor);
    }

    @Test
    public void testCreateDtlsExecutor() {
        Config config = new Config();
        State state = new State(config);
        WorkflowExecutor executor =
                WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DTLS, state);
        assertNotNull(executor);
        assertTrue(executor instanceof DTLSWorkflowExecutor);
    }

    @Test
    public void testCreateThreadedServerExecutorWithTls() {
        Config config = new Config();
        config.setHighestProtocolVersion(ProtocolVersion.TLS12);
        State state = new State(config);
        WorkflowExecutor executor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        WorkflowExecutorType.THREADED_SERVER, state);
        assertNotNull(executor);
        assertTrue(executor instanceof ThreadedServerWorkflowExecutor);
    }

    @Test
    public void testThreadedServerExecutorWithDtlsThrowsException() {
        Config config = new Config();
        config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        State state = new State(config);

        UnsupportedOperationException exception =
                assertThrows(
                        UnsupportedOperationException.class,
                        () ->
                                WorkflowExecutorFactory.createWorkflowExecutor(
                                        WorkflowExecutorType.THREADED_SERVER, state));

        assertTrue(
                exception
                        .getMessage()
                        .contains("ThreadedServerWorkflowExecutor is not supported for DTLS"));
        assertTrue(exception.getMessage().contains("DatagramSocket API"));
    }

    @Test
    public void testThreadedServerExecutorWithDtls10ThrowsException() {
        Config config = new Config();
        config.setHighestProtocolVersion(ProtocolVersion.DTLS10);
        State state = new State(config);

        UnsupportedOperationException exception =
                assertThrows(
                        UnsupportedOperationException.class,
                        () ->
                                WorkflowExecutorFactory.createWorkflowExecutor(
                                        WorkflowExecutorType.THREADED_SERVER, state));

        assertTrue(
                exception
                        .getMessage()
                        .contains("ThreadedServerWorkflowExecutor is not supported for DTLS"));
    }

    @Test
    public void testThreadedServerExecutorWithNullProtocolVersion() {
        Config config = new Config();
        config.setHighestProtocolVersion(null);
        // Pass a pre-defined workflow trace to avoid State creating a default one which requires
        // protocol version
        WorkflowTrace trace = new WorkflowTrace();
        State state = new State(config, trace);

        // Should not throw exception when protocol version is null
        WorkflowExecutor executor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        WorkflowExecutorType.THREADED_SERVER, state);
        assertNotNull(executor);
        assertTrue(executor instanceof ThreadedServerWorkflowExecutor);
    }
}
