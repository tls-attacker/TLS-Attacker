/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionPreparatorTest {

    private TlsContext context;
    private PaddingExtensionMessage message;
    private PaddingExtensionPreparator preparator;
    private int expectedLength;
    private byte[] expectedPayload;

    /**
     * Some initial set up.
     */
    @Before
    public void setUp() {
        context = new TlsContext();
        message = new PaddingExtensionMessage();
        preparator = new PaddingExtensionPreparator(context, message);
    }

    /**
     * Tests the preparator of the padding extension message.
     */
    @Test
    public void testPaddingExtensionPreparator() {
        expectedLength = 6;
        expectedPayload = new byte[expectedLength];

        context.setPaddingExtensionLength(expectedLength);
        preparator.prepare();

        assertEquals(expectedLength, (int) message.getExtensionLength().getValue());
        assertArrayEquals(expectedPayload, message.getPaddingBytes().getValue());

    }

}
