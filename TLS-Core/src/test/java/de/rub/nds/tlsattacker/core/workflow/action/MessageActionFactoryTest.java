/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
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
        TlsConfig config = TlsConfig.createConfig();
        MessageAction action = MessageActionFactory.createAction(ConnectionEnd.CLIENT, ConnectionEnd.CLIENT,
                new AlertMessage(config));
        assertEquals(action.getClass(), SendAction.class);
        action = MessageActionFactory
                .createAction(ConnectionEnd.CLIENT, ConnectionEnd.SERVER, new AlertMessage(config));
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory
                .createAction(ConnectionEnd.SERVER, ConnectionEnd.CLIENT, new AlertMessage(config));
        assertEquals(action.getClass(), ReceiveAction.class);
        action = MessageActionFactory
                .createAction(ConnectionEnd.SERVER, ConnectionEnd.SERVER, new AlertMessage(config));
        assertEquals(action.getClass(), SendAction.class);
        assertTrue(action.getConfiguredMessages().size() == 1);
    }

    /**
     * Test of createAction method, of class MessageActionFactory.
     */
    @Test
    public void testCreateActionMultiple() {
        TlsConfig config = TlsConfig.createConfig();
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new ArbitraryMessage());
        messages.add(new AlertMessage(config));
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
