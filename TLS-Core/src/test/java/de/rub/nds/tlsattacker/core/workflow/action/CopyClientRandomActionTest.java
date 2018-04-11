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
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class CopyClientRandomActionTest {
    private State state;
    private TlsContext tlsContextServer1;
    private TlsContext tlsContextServer2;
    private CopyClientRandomAction action;

    @Before
    public void setUp() {

        Config config = Config.createConfig();
        action = new CopyClientRandomAction("server1", "server2");
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        trace.addConnection(new OutboundConnection("server1", 444, "localhost"));
        trace.addConnection(new OutboundConnection("server2", 445, "localhost"));

        // TLS-Contexts are created during state initialization
        state = new State(config, trace);
        tlsContextServer1 = state.getTlsContext("server1");
        tlsContextServer2 = state.getTlsContext("server2");

        tlsContextServer1.setClientRandom(new byte[] { 1, 2 });
        tlsContextServer2.setClientRandom(new byte[] { 0, 0 });
    }

    @After
    public void tearDown() {

    }

    /**
     * Test of execute method, of class ChangeClientRandomAction.
     */
    @Test
    public void testExecute() {
        action.execute(state);

        assertArrayEquals(tlsContextServer1.getClientRandom(), tlsContextServer2.getClientRandom());
        assertArrayEquals(tlsContextServer2.getClientRandom(), new byte[] { 1, 2 });
        assertTrue(action.isExecuted());
    }

    /**
     * Test of getSrc/DstContextAlias methods, of class
     * ChangeClientRandomAction.
     */
    @Test
    public void testGetAlias() {
        assertEquals(action.getSrcContextAlias(), "server1");
        assertEquals(action.getDstContextAlias(), "server2");
    }

    /**
     * Test of equals method, of class ChangeClientRandomAction.
     */
    @Test
    public void testEquals() {
        assertEquals(action, action);
        assertNotEquals(action, new CopyClientRandomAction("server1", "null"));
        assertNotEquals(action, new CopyClientRandomAction("null", "server2"));
        assertNotEquals(action, new CopyClientRandomAction("null", "null"));
    }

    /**
     * Test of getAllAliases method, of class ChangeClientRandomAction.
     */
    @Test
    public void testGetAllAliases() {
        String[] aliases = action.getAllAliases().toArray(new String[2]);

        assertEquals(aliases.length, 2);
        assertTrue(aliases[0].equals("server1") || aliases[0].equals("server2"));
        assertTrue(aliases[1].equals("server1") || aliases[1].equals("server2"));
        assertNotEquals(aliases[0], aliases[1]);

    }

}
