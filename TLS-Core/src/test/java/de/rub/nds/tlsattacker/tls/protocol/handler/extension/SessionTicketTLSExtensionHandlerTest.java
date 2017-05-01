/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SessionTicketTLSExtensionHandlerTest extends ExtensionHandlerTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] sessionTicket;
    private final byte[] expectedBytes;
    private final int startParsing;

    public SessionTicketTLSExtensionHandlerTest(ExtensionType extensionType, int extensionLength, byte[] sessionTicket,
            byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.sessionTicket = sessionTicket;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    /**
     * Parameterized set up of the test vector.
     *
     * @return test vector (extensionType, extensionLength, extensionPayload,
     *         expectedBytes)
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.SESSION_TICKET, 0, new byte[0],
                ArrayConverter.hexStringToByteArray("00230000"), 0 } });
    }

    /**
     * Some initial set up.
     */
    @Override
    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SessionTicketTLSExtensionHandler(context);
    }

    @Override
    public void testAdjustTLSContext() {
        SessionTicketTLSExtensionMessage message = new SessionTicketTLSExtensionMessage();
        message.setTicket(sessionTicket);
        message.setExtensionLength(extensionLength);

        handler.adjustTLSContext(message);

        assertArrayEquals(sessionTicket, context.getSessionTicketTLS());
    }

    @Override
    public void testGetParser() {
        assertTrue(handler.getParser(expectedBytes, startParsing) instanceof SessionTicketTLSExtensionParser);
    }

    @Override
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new SessionTicketTLSExtensionMessage()) instanceof SessionTicketTLSExtensionPreparator);
    }

    @Override
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new SessionTicketTLSExtensionMessage()) instanceof SessionTicketTLSExtensionSerializer);
    }

}
