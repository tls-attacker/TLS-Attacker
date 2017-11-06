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
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.transport.ClientConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
import java.util.LinkedList;
import java.util.List;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MessageActionFactoryTest {

    Config config;
    ConnectionEnd clientConnectionEnd;
    ConnectionEnd serverConnectionEnd;

    @Before
    public void setUp() {
        config = Config.createConfig();
        clientConnectionEnd = new ClientConnectionEnd();
        serverConnectionEnd = new ServerConnectionEnd();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of createAction method, of class MessageActionFactory.
     */
    @Test
    public void testCreateActionOne() {
        MessageAction action = MessageActionFactory.createAction(clientConnectionEnd, ConnectionEndType.CLIENT,
                new AlertMessage(config));
        assertEquals(action.getClass(), SendAction.class);
        action = MessageActionFactory.createAction(clientConnectionEnd, ConnectionEndType.SERVER, new AlertMessage(
                config));
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(serverConnectionEnd, ConnectionEndType.CLIENT, new AlertMessage(
                config));
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(serverConnectionEnd, ConnectionEndType.SERVER, new AlertMessage(
                config));
        assertEquals(action.getClass(), SendAction.class);
        assertTrue(action.messages.size() == 1);
    }

    /**
     * Test of createAction method, of class MessageActionFactory.
     */
    @Test
    public void testCreateActionMultiple() {
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new ArbitraryMessage());
        messages.add(new AlertMessage(config));
        MessageAction action = MessageActionFactory.createAction(clientConnectionEnd, ConnectionEndType.CLIENT,
                messages);
        assertEquals(action.getClass(), SendAction.class);
        action = MessageActionFactory.createAction(clientConnectionEnd, ConnectionEndType.SERVER, messages);
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(serverConnectionEnd, ConnectionEndType.CLIENT, messages);
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(serverConnectionEnd, ConnectionEndType.SERVER, messages);
        assertEquals(action.getClass(), SendAction.class);
        assertTrue(action.messages.size() == 2);
    }

}
