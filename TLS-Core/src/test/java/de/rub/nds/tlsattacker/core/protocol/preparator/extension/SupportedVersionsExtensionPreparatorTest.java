/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SupportedVersionsExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class SupportedVersionsExtensionPreparatorTest {

    private SupportedVersionsExtensionPreparator preparator;
    private SupportedVersionsExtensionMessage message;
    private TlsContext context;

    public SupportedVersionsExtensionPreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new SupportedVersionsExtensionMessage();
        preparator = new SupportedVersionsExtensionPreparator(context.getChooser(), message,
                new SupportedVersionsExtensionSerializer(message));
    }

    /**
     * Test of prepare method, of class SupportedVersionsExtensionPreparator.
     */
    @Test
    public void testPrepare() {
        LinkedList<ProtocolVersion> supportedVersions = new LinkedList<>();
        supportedVersions.add(ProtocolVersion.TLS13);
        supportedVersions.add(ProtocolVersion.TLS12);
        context.getConfig().setSupportedVersions(supportedVersions);
        preparator.prepare();
        assertArrayEquals(message.getSupportedVersions().getValue(),
                ArrayConverter.concatenate(ProtocolVersion.TLS13.getValue(), ProtocolVersion.TLS12.getValue()));
        assertTrue(message.getSupportedVersionsLength().getValue() == 4);
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
