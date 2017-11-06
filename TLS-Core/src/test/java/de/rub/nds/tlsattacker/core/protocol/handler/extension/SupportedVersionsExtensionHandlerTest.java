/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SupportedVersionsExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SupportedVersionsExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SupportedVersionsExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class SupportedVersionsExtensionHandlerTest {

    private SupportedVersionsExtensionHandler handler;
    private TlsContext context;

    public SupportedVersionsExtensionHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SupportedVersionsExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class
     * SupportedVersionsExtensionHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        msg.setSupportedVersions(ArrayConverter.concatenate(ProtocolVersion.TLS12.getValue(),
                ProtocolVersion.TLS13.getValue()));
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientSupportedProtocolVersions().size() == 2);
        assertEquals(context.getHighestClientProtocolVersion().getValue(), ProtocolVersion.TLS13.getValue());
    }

    @Test
    public void testAdjustTLSContextBadVersions() {
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        msg.setSupportedVersions(new byte[] { 0, 1, 2, 3, 3, 3 });
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientSupportedProtocolVersions().size() == 1);
        assertEquals(context.getHighestClientProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
    }

    /**
     * Test of getParser method, of class SupportedVersionsExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0, 2 }, 0) instanceof SupportedVersionsExtensionParser);
    }

    /**
     * Test of getPreparator method, of class SupportedVersionsExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new SupportedVersionsExtensionMessage()) instanceof SupportedVersionsExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class SupportedVersionsExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new SupportedVersionsExtensionMessage()) instanceof SupportedVersionsExtensionSerializer);
    }
}
