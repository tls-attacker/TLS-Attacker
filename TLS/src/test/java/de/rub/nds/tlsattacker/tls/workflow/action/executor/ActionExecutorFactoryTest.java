/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author ic0ns
 */
public class ActionExecutorFactoryTest {

    public ActionExecutorFactoryTest() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of createActionExecutor method, of class ActionExecutorFactory.
     */
    @Test
    public void testCreateActionExecutor() {
        ActionExecutor executor = ActionExecutorFactory.createActionExecutor(new TlsContext(), new WorkflowContext(),
                ExecutorType.DTLS);
        assertTrue(executor.getClass().equals(DTLSActionExecutor.class));
        executor = ActionExecutorFactory
                .createActionExecutor(new TlsContext(), new WorkflowContext(), ExecutorType.TLS);
        assertTrue(executor.getClass().equals(TLSActionExecutor.class));
    }

}
