/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SessionTicketTLSExtensionHandlerTest;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SessionTicketTLSExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SessionTicketTLSExtensionPreparatorTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] extensionPayload;
    private final byte[] expectedBytes;
    private final int startParsing;
    private TlsContext context;
    private SessionTicketTLSExtensionMessage message;
    private SessionTicketTLSExtensionPreparator preparator;

    /**
     * Constructor for parameterized setup.
     *
     * @param extensionType
     * @param extensionLength
     * @param extensionPayload
     * @param expectedBytes
     * @param startParsing
     */
    public SessionTicketTLSExtensionPreparatorTest(ExtensionType extensionType, int extensionLength,
            byte[] extensionPayload, byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extensionPayload = extensionPayload;
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
     * Some initial setup.
     */
    @Before
    public void setUp() {
        context = new TlsContext();
        message = new SessionTicketTLSExtensionMessage();
        preparator = new SessionTicketTLSExtensionPreparator(context, (SessionTicketTLSExtensionMessage) message);
    }

    /**
     * Tests the preparator of the SessionTicketTLSExtensionPreparator.
     */
    @Test
    public void testPreparator() {
        context.getConfig().setTLSSessionTicket(new byte[0]);
        preparator.prepare();

        assertEquals(extensionLength, (int) message.getExtensionLength().getValue());
        assertArrayEquals(extensionPayload, message.getTicket().getValue());
    }

}
