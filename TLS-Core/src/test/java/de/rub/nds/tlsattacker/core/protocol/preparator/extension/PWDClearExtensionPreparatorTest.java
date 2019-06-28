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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDClearExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PWDClearExtensionPreparatorTest {

    private TlsContext context;
    private PWDClearExtensionMessage message;
    private PWDClearExtensionPreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new PWDClearExtensionMessage();
        preparator = new PWDClearExtensionPreparator(context.getChooser(), message, new PWDClearExtensionSerializer(
                message));
    }

    @Test
    public void testPreparator() {
        context.setClientPWDUsername("Bob");
        preparator.prepare();

        assertArrayEquals(ExtensionType.PWD_CLEAR.getValue(), message.getExtensionType().getValue());
        assertEquals(3 + 1, (long) message.getExtensionLength().getValue());

    }

}