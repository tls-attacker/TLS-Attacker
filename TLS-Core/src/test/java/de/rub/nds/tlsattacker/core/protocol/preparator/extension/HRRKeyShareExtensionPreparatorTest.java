/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.HRRKeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class HRRKeyShareExtensionPreparatorTest {

    private HRRKeyShareExtensionPreparator preparator;
    private HRRKeyShareExtensionMessage message;
    private TlsContext context;

    public HRRKeyShareExtensionPreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new HRRKeyShareExtensionMessage();
        preparator = new HRRKeyShareExtensionPreparator(context.getChooser(), message,
                new HRRKeyShareExtensionSerializer(message));
    }

    /**
     * Test of prepare method, of class HRRKeyShareExtensionPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();
        assertArrayEquals(message.getSelectedGroup().getValue(), context.getConfig().getDefaultSelectedNamedGroup()
                .getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
