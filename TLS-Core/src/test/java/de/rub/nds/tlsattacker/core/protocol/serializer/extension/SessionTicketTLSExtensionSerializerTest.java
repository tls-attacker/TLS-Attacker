/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

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

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] sessionTicket;
    private final byte[] expectedBytes;
    private SessionTicketTLSExtensionMessage message;

    /**
     * Constructor for parameterized setup.
     *
     * @param extensionType
     * @param extensionLength
     * @param sessionTicket
     * @param expectedBytes
     * @param startParsing
     */
    public SessionTicketTLSExtensionSerializerTest(ExtensionType extensionType, int extensionLength,
            byte[] sessionTicket, byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.sessionTicket = sessionTicket;
        this.expectedBytes = expectedBytes;
    }

    /**
     * Tests the serializeExtensionContent method of the
     * SessionTicketTLSExtensionSerializer class
     */
    @Test
    public void testSerializeExtensionContent() {
        message = new SessionTicketTLSExtensionMessage();
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);
        message.setTicket(sessionTicket);

        SessionTicketTLSExtensionSerializer serializer = new SessionTicketTLSExtensionSerializer(message);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }

}
