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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class MessageActionFactoryTest {

    Config config;
    AliasedConnection clientConnection;
    AliasedConnection serverConnection;

    @Before
    public void setUp() {
        config = Config.createConfig();
        clientConnection = new OutboundConnection();
        serverConnection = new InboundConnection();
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of createAction method, of class MessageActionFactory.
     */
    @Test
    public void testCreateActionOne() {
        MessageAction action = MessageActionFactory.createAction(clientConnection, ConnectionEndType.CLIENT,
                new AlertMessage(config));
        assertEquals(action.getClass(), SendAction.class);
        action = MessageActionFactory
                .createAction(clientConnection, ConnectionEndType.SERVER, new AlertMessage(config));
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory
                .createAction(serverConnection, ConnectionEndType.CLIENT, new AlertMessage(config));
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory
                .createAction(serverConnection, ConnectionEndType.SERVER, new AlertMessage(config));
        assertEquals(action.getClass(), SendAction.class);
        assertTrue(action.messages.size() == 1);
    }

    /**
     * Test of createAction method, of class MessageActionFactory.
     */
    @Test
    public void testCreateActionMultiple() {
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new ChangeCipherSpecMessage());
        messages.add(new AlertMessage(config));
        MessageAction action = MessageActionFactory.createAction(clientConnection, ConnectionEndType.CLIENT, messages);
        assertEquals(action.getClass(), SendAction.class);
        action = MessageActionFactory.createAction(clientConnection, ConnectionEndType.SERVER, messages);
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(serverConnection, ConnectionEndType.CLIENT, messages);
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory.createAction(serverConnection, ConnectionEndType.SERVER, messages);
        assertEquals(action.getClass(), SendAction.class);
        assertTrue(action.messages.size() == 2);
    }

    /**
     * Test of createAsciiAction method, of class MessageActionFactory.
     */
    @Test
    public void testCreateAsciiAction() {
        AsciiAction action = MessageActionFactory.createAsciiAction(clientConnection, ConnectionEndType.CLIENT, "", "");
        assertEquals(action.getClass(), SendAsciiAction.class);
        action = MessageActionFactory.createAsciiAction(clientConnection, ConnectionEndType.SERVER, "", "");
        assertEquals(action.getClass(), GenericReceiveAsciiAction.class);
        action = MessageActionFactory.createAsciiAction(serverConnection, ConnectionEndType.CLIENT, "", "");
        assertEquals(action.getClass(), GenericReceiveAsciiAction.class);
        action = MessageActionFactory.createAsciiAction(serverConnection, ConnectionEndType.SERVER, "", "");
        assertEquals(action.getClass(), SendAsciiAction.class);
    }
}
