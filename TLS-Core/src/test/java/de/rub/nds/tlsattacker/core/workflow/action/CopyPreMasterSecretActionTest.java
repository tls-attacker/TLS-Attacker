/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CopyPreMasterSecretActionTest {
    private State state;
    private TlsContext tlsContextServer1;
    private TlsContext tlsContextServer2;
    private CopyPreMasterSecretAction action;

    @Before
    public void setUp() {
        Config config = Config.createConfig();
        action = new CopyPreMasterSecretAction("server1", "server2");
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        trace.addConnection(new OutboundConnection("server1", 444, "localhost"));
        trace.addConnection(new OutboundConnection("server2", 445, "localhost"));

        state = new State(config, trace);
        tlsContextServer1 = state.getTlsContext("server1");
        tlsContextServer2 = state.getTlsContext("server2");
        tlsContextServer1.setPreMasterSecret(new byte[] { 1, 2 });
        tlsContextServer2.setPreMasterSecret(new byte[] { 3, 4 });
    }

    /**
     * Test of execute method, of class CopyPreMasterSecretActionTest.
     */
    @Test
    public void testExecute() {
        action.execute(state);
        assertArrayEquals(tlsContextServer1.getPreMasterSecret(), tlsContextServer2.getPreMasterSecret());
        assertArrayEquals(tlsContextServer1.getPreMasterSecret(), new byte[] { 1, 2 });
        assertArrayEquals(tlsContextServer2.getPreMasterSecret(), new byte[] { 1, 2 });
        assertTrue(action.isExecuted());
    }

    /**
     * Test of getSrc/DstContextAlias methods, of class CopyPreMasterSecretAction
     */
    @Test
    public void testGetAlias() {
        assertEquals(action.getSrcContextAlias(), "server1");
        assertEquals(action.getDstContextAlias(), "server2");
    }

    /**
     * Test of getAllAliases method, of class ChangeClientRandomAction.
     */
    @Test
    public void testGetAllAliases() {
        String[] aliases = action.getAllAliases().toArray(new String[2]);
        assertTrue(aliases[0].equals("server1") || aliases[0].equals("server2"));
        assertTrue(aliases[1].equals("server1") || aliases[1].equals("server2"));
        assertNotEquals(aliases[0], aliases[1]);
    }

    /**
     * Test of equals method, of class CopyPreMasterSecretAction.
     */
    @Test
    public void testEquals() {
        assertEquals(action, action);
        assertNotEquals(action, new CopyPreMasterSecretAction("server1", "null"));
        assertNotEquals(action, new CopyPreMasterSecretAction("null", "server2"));
        assertNotEquals(action, new CopyPreMasterSecretAction("null", "null"));
    }
}
