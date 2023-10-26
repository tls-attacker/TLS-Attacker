/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

abstract class AbstractActionTest<T extends TlsAction> {

    protected final Config config;

    private final Class<T> actionClass;
    protected final T action;

    protected WorkflowTrace trace;
    protected State state;

    AbstractActionTest(T action, Class<T> actionClass) {
        this.config = Config.createConfig();
        this.action = action;
        this.actionClass = actionClass;
        createWorkflowTraceAndState();
    }

    protected void createWorkflowTraceAndState() {
        trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);
    }

    @Test
    public void testExecute() throws Exception {
        action.execute(state);
        assertTrue(action.isExecuted());
        assertTrue((action.executedAsPlanned()));
    }

    @Test
    public void testDoubleExecuteThrowsActionExecutionException() {
        action.execute(state);
        assertThrows(ActionExecutionException.class, () -> action.execute(state));
    }

    @Test
    public void testReset() {
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testMarshalingEmptyActionYieldsMinimalOutput() throws JAXBException, IOException {
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(actionClass);
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testMarshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(actionClass);
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }
}
