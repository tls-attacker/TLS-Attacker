/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParserTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class SessionTicketTLSExtensionSerializerTest {

    /**
     * Gets the test vectors of the SessionTicketTLSExtensionHandlerTest class.
     *
     * @return Collection of the parameters
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SessionTicketTLSExtensionParserTest.generateData();
    }

    private final byte[] sessionTicket;
    private final byte[] expectedBytes;
    private SessionTicketTLSExtensionMessage message;

    /**
     * Constructor for parameterized setup.
     *
     * @param sessionTicket
     * @param expectedBytes
     */
    public SessionTicketTLSExtensionSerializerTest(byte[] sessionTicket, byte[] expectedBytes) {
        this.sessionTicket = sessionTicket;
        this.expectedBytes = expectedBytes;
    }

    /**
     * Tests the serializeExtensionContent method of the SessionTicketTLSExtensionSerializer class
     */
    @Test
    public void testSerializeExtensionContent() {
        message = new SessionTicketTLSExtensionMessage();
        message.setTicket(sessionTicket);

        SessionTicketTLSExtensionSerializer serializer = new SessionTicketTLSExtensionSerializer(message);

        assertArrayEquals(expectedBytes, serializer.serializeExtensionContent());
    }

}
