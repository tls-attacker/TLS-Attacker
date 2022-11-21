/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class SessionTicketTlsExtensionHandlerTest
    extends AbstractExtensionMessageHandlerTest<SessionTicketTLSExtensionMessage, SessionTicketTlsExtensionHandler> {

    public SessionTicketTlsExtensionHandlerTest() {
        super(SessionTicketTLSExtensionMessage::new, SessionTicketTlsExtensionHandler::new, () -> {
            Config config = Config.createConfig();
            config.setDefaultRunningMode(RunningModeType.SERVER);
            return new TlsContext(config);
        });
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
    }

    /**
     * Tests the adjustTLSContext of the SessionTicketTlsExtensionHandler class
     */
    @Test
    @Override
    public void testAdjustTLSContext() {
        NewSessionTicketMessage newSessionTicketMessage = new NewSessionTicketMessage();
        newSessionTicketMessage.getHandler(context).getPreparator(newSessionTicketMessage).prepare();
        SessionTicket ticket = newSessionTicketMessage.getTicket();

        SessionTicketTLSExtensionMessage message = new SessionTicketTLSExtensionMessage();
        handler.getPreparator(message).prepare();
        message.setSessionTicket(ticket);
        message.setExtensionLength(handler.getSerializer(message).serialize().length);
        context.setClientSessionId(context.getConfig().getDefaultClientTicketResumptionSessionId());

        handler.adjustTLSContext(message);
        assertArrayEquals(context.getMasterSecret(), context.getChooser().getMasterSecret());
    }
}
