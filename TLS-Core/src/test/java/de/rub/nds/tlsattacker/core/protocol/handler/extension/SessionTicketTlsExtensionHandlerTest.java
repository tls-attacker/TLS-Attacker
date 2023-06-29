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
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
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
                    Config config = Config.createConfig();
                    config.setDefaultRunningMode(RunningModeType.SERVER);
                    return new TlsContext(config);
                });
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
    }

    /** Tests the adjustTLSExtensionContext of the SessionTicketTlsExtensionHandler class */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        NewSessionTicketMessage newSessionTicketMessage = new NewSessionTicketMessage();
        newSessionTicketMessage.getPreparator(context).prepare();
        SessionTicket ticket = newSessionTicketMessage.getTicket();

        SessionTicketTLSExtensionMessage message = new SessionTicketTLSExtensionMessage();
        message.getPreparator(context).prepare();
        message.setSessionTicket(ticket);
        message.setExtensionLength(message.getSerializer(context).serialize().length);
        context.setClientSessionId(context.getConfig().getDefaultClientTicketResumptionSessionId());

        handler.adjustTLSExtensionContext(message);
        assertArrayEquals(context.getMasterSecret(), context.getChooser().getMasterSecret());
    }
}
