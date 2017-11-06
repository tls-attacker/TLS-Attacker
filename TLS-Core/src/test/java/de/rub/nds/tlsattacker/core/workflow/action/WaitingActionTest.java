/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXB;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;


public class WaitingActionTest {

    private State state;
    private TlsContext tlsContext;

    private WaitingAction action;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        Config config = Config.createConfig();
        state = new State(config, new WorkflowTrace(config));
        action = new WaitingAction(10);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of execute method, of class WaitingAction.
     * 
     * @throws java.io.IOException
     */
    @Test
    public void testExecute() throws WorkflowExecutionException, IOException {
        long time = System.currentTimeMillis();
        action.execute(state);
        assertTrue(10l <= System.currentTimeMillis() - time);
    }

    /**
     * Test of reset method, of class WaitingAction.
     * 
     * @throws java.io.IOException
     */
    @Test
    public void testReset() throws WorkflowExecutionException, IOException {
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
    }

    /*
     * Test of JAXB.marshal and JAXB.unmarshal
     */

    @Test
    public void testJAXB() {
        StringWriter writer = new StringWriter();
        JAXB.marshal(action, writer);
        WaitingAction action2 = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), WaitingAction.class);
        assertEquals(action.getTime(), action2.getTime());
    }

}
