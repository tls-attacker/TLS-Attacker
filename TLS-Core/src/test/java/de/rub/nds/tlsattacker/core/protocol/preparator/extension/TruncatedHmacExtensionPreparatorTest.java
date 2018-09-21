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
import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TruncatedHmacExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class TruncatedHmacExtensionPreparatorTest {

    private final ExtensionType extensionType = ExtensionType.TRUNCATED_HMAC;
    private final int extensionLength = 0;
    private TlsContext context;
    private TruncatedHmacExtensionMessage message;
    private TruncatedHmacExtensionPreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new TruncatedHmacExtensionMessage();
        preparator = new TruncatedHmacExtensionPreparator(context.getChooser(), message,
                new TruncatedHmacExtensionSerializer(message));
    }

    @Test
    public void testPreparator() {
        preparator.prepare();

        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
    }

}
