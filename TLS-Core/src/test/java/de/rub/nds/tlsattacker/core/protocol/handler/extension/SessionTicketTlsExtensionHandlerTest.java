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
import de.rub.nds.tlsattacker.core.protocol.handler.NewSessionTicketHandler;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

public class SessionTicketTlsExtensionHandlerTest {

    private static final byte[] IV = ArrayConverter.hexStringToByteArray("60ac89f55a58c84bfa9820bd2ecd505d");

    private TlsContext context;
    private SessionTicketTlsExtensionHandler handler;

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
     * Tests the adjustTLSContext of the SessionTicketTlsExtensionHandler class
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

    /**
     * Tests the getParser of the SessionTicketTlsExtensionHandler class
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0, context.getConfig()) instanceof SessionTicketTLSExtensionParser);
    }

    /**
     * Tests the getPreparator of the SessionTicketTlsExtensionHandler class
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler
            .getPreparator(new SessionTicketTLSExtensionMessage()) instanceof SessionTicketTLSExtensionPreparator);
    }

    /**
     * Tests the getSerializer of the SessionTicketTlsExtensionHandler class
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler
            .getSerializer(new SessionTicketTLSExtensionMessage()) instanceof SessionTicketTLSExtensionSerializer);
    }

}
