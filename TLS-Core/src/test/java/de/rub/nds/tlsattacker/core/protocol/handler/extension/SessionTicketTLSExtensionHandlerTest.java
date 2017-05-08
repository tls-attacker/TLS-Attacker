/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
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

    /**
     * Constructor for parameterized setup.
     *
     * @param extensionType
     * @param extensionLength
     * @param sessionTicket
     * @param expectedBytes
     * @param startParsing
     */
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

    /**
     * Tests the adjustTLSContext of the SessionTicketTLSExtensionHandler class
     */
    @Override
    public void testAdjustTLSContext() {
        SessionTicketTLSExtensionMessage message = new SessionTicketTLSExtensionMessage();
        message.setTicket(sessionTicket);
        message.setExtensionLength(extensionLength);

        handler.adjustTLSContext(message);

        assertArrayEquals(sessionTicket, context.getSessionTicketTLS());
    }

    /**
     * Tests the getParser of the SessionTicketTLSExtensionHandler class
     */
    @Override
    public void testGetParser() {
        assertTrue(handler.getParser(expectedBytes, startParsing) instanceof SessionTicketTLSExtensionParser);
    }

    /**
     * Tests the getPreparator of the SessionTicketTLSExtensionHandler class
     */
    @Override
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new SessionTicketTLSExtensionMessage()) instanceof SessionTicketTLSExtensionPreparator);
    }

    /**
     * Tests the getSerializer of the SessionTicketTLSExtensionHandler class
     */
    @Override
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new SessionTicketTLSExtensionMessage()) instanceof SessionTicketTLSExtensionSerializer);
    }

}
