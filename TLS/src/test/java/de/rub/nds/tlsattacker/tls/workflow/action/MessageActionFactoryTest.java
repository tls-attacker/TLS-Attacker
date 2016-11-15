/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import java.util.LinkedList;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MessageActionFactoryTest {

    public MessageActionFactoryTest() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of createAction method, of class MessageActionFactory.
     */
    @Test
    public void testCreateActionOne() {
        MessageAction action = MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.CLIENT,
                new AlertMessage());
        assertEquals(action.getClass(), SendAction.class);
        action = MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.SERVER, new AlertMessage());
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(ConnectionEnd.SERVER, ConnectionEnd.CLIENT, new AlertMessage());
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(ConnectionEnd.SERVER, ConnectionEnd.SERVER, new AlertMessage());
        assertEquals(action.getClass(), SendAction.class);
        assertTrue(action.getConfiguredMessages().size() == 1);
    }

    /**
     * Test of createAction method, of class MessageActionFactory.
     */
    @Test
    public void testCreateActionMultiple() {
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new ArbitraryMessage());
        messages.add(new AlertMessage());
        MessageAction action = MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.CLIENT, messages);
        assertEquals(action.getClass(), SendAction.class);
        action = MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.SERVER, messages);
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(ConnectionEnd.SERVER, ConnectionEnd.CLIENT, messages);
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(ConnectionEnd.SERVER, ConnectionEnd.SERVER, messages);
        assertEquals(action.getClass(), SendAction.class);
        assertTrue(action.getConfiguredMessages().size() == 2);
    }

}
