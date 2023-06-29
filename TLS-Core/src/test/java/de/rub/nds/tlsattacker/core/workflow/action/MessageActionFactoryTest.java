/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MessageActionFactoryTest {

    private Config config;
    private AliasedConnection clientConnection;
    private AliasedConnection serverConnection;

    @BeforeEach
    public void setUp() {
        config = new Config();
        clientConnection = new OutboundConnection();
        serverConnection = new InboundConnection();
    }

    /** Test of createAction method, of class MessageActionFactory. */
    @Test
    public void testCreateActionOne() {
        MessageAction action =
                MessageActionFactory.createTLSAction(
                        config, clientConnection, ConnectionEndType.CLIENT, new AlertMessage());
        assertEquals(SendAction.class, action.getClass());
        action =
                MessageActionFactory.createTLSAction(
                        config, clientConnection, ConnectionEndType.SERVER, new AlertMessage());
        assertEquals(ReceiveAction.class, action.getClass());
        action =
                MessageActionFactory.createTLSAction(
                        config, serverConnection, ConnectionEndType.CLIENT, new AlertMessage());
        assertEquals(ReceiveAction.class, action.getClass());
        action =
                MessageActionFactory.createTLSAction(
                        config, serverConnection, ConnectionEndType.SERVER, new AlertMessage());
        assertEquals(SendAction.class, action.getClass());
        assertEquals(1, action.messages.size());
    }

    /** Test of createAction method, of class MessageActionFactory. */
    @Test
    public void testCreateActionMultiple() {
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(new ChangeCipherSpecMessage());
        messages.add(new AlertMessage());
        MessageAction action =
                MessageActionFactory.createTLSAction(
                        config, clientConnection, ConnectionEndType.CLIENT, messages);
        assertEquals(SendAction.class, action.getClass());
        action =
                MessageActionFactory.createTLSAction(
                        config, clientConnection, ConnectionEndType.SERVER, messages);
        assertEquals(ReceiveAction.class, action.getClass());
        action =
                MessageActionFactory.createTLSAction(
                        config, serverConnection, ConnectionEndType.CLIENT, messages);
        assertEquals(ReceiveAction.class, action.getClass());
        action =
                MessageActionFactory.createTLSAction(
                        config, serverConnection, ConnectionEndType.SERVER, messages);
        assertEquals(SendAction.class, action.getClass());
        assertEquals(2, action.messages.size());
    }
}
