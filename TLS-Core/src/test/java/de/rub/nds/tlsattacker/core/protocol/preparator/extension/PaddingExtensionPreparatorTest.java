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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class PaddingExtensionPreparatorTest {

    private final int extensionLength = 6;
    private final byte[] extensionPayload = new byte[] { 0, 0, 0, 0, 0, 0 };
    private TlsContext context;
    private PaddingExtensionMessage message;
    private PaddingExtensionPreparator preparator;

    /**
     * Some initial set up.
     */
    @Before
    public void setUp() {
        context = new TlsContext();
        message = new PaddingExtensionMessage();
        preparator = new PaddingExtensionPreparator(context, (PaddingExtensionMessage) message);
    }

    /**
     * Tests the preparator of the padding extension message.
     */

    @Test
    public void testPreparator() {
        context.getConfig().setDefaultPaddingExtensionBytes(extensionPayload);
        preparator.prepare();

        assertArrayEquals(ExtensionType.PADDING.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (int) message.getExtensionLength().getValue());
        assertArrayEquals(extensionPayload, message.getPaddingBytes().getValue());

    }

}
