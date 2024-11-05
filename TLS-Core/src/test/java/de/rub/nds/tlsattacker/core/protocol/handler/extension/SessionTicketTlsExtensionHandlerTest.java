/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class SessionTicketTlsExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                SessionTicketTLSExtensionMessage, SessionTicketTLSExtensionHandler> {

    public SessionTicketTlsExtensionHandlerTest() {
        super(
                SessionTicketTLSExtensionMessage::new,
                SessionTicketTLSExtensionHandler::new,
                () -> {
                    Config config = new Config();
                    config.setDefaultRunningMode(RunningModeType.SERVER);
                    return new Context(new State(config), new InboundConnection()).getTlsContext();
                });
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
    }

    /** Tests the adjustTLSExtensionContext of the SessionTicketTlsExtensionHandler class */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        NewSessionTicketMessage newSessionTicketMessage = new NewSessionTicketMessage();
        newSessionTicketMessage.getPreparator(tlsContext.getContext()).prepare();
        SessionTicket ticket = newSessionTicketMessage.getTicket();

        SessionTicketTLSExtensionMessage message = new SessionTicketTLSExtensionMessage();
        message.getPreparator(tlsContext.getContext()).prepare();
        message.setSessionTicket(ticket);
        message.setExtensionLength(
                message.getSerializer(tlsContext.getContext()).serialize().length);
        tlsContext.setClientSessionId(
                tlsContext.getConfig().getDefaultClientTicketResumptionSessionId());

        handler.adjustTLSExtensionContext(message);
        assertArrayEquals(tlsContext.getMasterSecret(), tlsContext.getChooser().getMasterSecret());
    }
}
