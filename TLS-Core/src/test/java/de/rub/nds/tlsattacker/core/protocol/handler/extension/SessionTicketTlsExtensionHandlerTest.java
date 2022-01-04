/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class SessionTicketTlsExtensionHandlerTest {

    private static final byte[] IV = ArrayConverter.hexStringToByteArray("60ac89f55a58c84bfa9820bd2ecd505d");

    private TlsContext context;
    private SessionTicketTLSExtensionHandler handler;

    /**
     * Some initial set up.
     */
    @Before
    public void setUp() throws CryptoException {
        Config config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.SERVER);

        context = new TlsContext(config);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);

        handler = new SessionTicketTlsExtensionHandler(context);
    }

    /**
     * Tests the adjustContext of the SessionTicketTlsExtensionHandler class
     */
    @Test
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
