/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.SessionTicketTLSExtensionHandlerTest;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SessionTicketTLSExtensionMessage;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SessionTicketTLSExtensionSerializerTest extends ExtensionSerializerTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] sessionTicket;
    private final byte[] expectedBytes;
    private final int startParsing;

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
        this.startParsing = startParsing;
    }

    /**
     * Gets the test vectors of the SessionTicketTLSExtensionHandlerTest class.
     *
     * @return Collection of the parameters
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SessionTicketTLSExtensionHandlerTest.generateData();
    }

    /**
     * Tests the serializeExtensionContent method of the
     * SessionTicketTLSExtensionSerializer class
     */
    @Test
    @Override
    public void testSerializeExtensionContent() {
        message = new SessionTicketTLSExtensionMessage();
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);
        ((SessionTicketTLSExtensionMessage) message).setTicket(sessionTicket);

        SessionTicketTLSExtensionSerializer serializer = new SessionTicketTLSExtensionSerializer(
                (SessionTicketTLSExtensionMessage) message);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }

}
