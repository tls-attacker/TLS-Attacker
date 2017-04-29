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
import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.PaddingExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.PaddingExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.PaddingExtensionSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.PaddingExtensionSerializerTest;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Collection;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class PaddingExtensionHandlerTest extends ExtensionHandlerTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] extensionPayload;
    private final byte[] expectedBytes;
    private final int startParsing;

    public PaddingExtensionHandlerTest(ExtensionType extensionType, int extensionLength, byte[] extensionPayload, byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return PaddingExtensionSerializerTest.generateData();
    }

    /**
     * Some initial set up.
     */
    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PaddingExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class PaddingExtensionHandler.
     */
    @Override
    @Test
    public void testAdjustTLSContext() {
        PaddingExtensionMessage msg = new PaddingExtensionMessage();
        msg.setPaddingBytes(extensionPayload);
        handler.adjustTLSContext(msg);
        assertEquals(context.getPaddingExtensionLength(), extensionLength);
    }

    /**
     * Test of getParser method, of class PaddingExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(expectedBytes, startParsing) instanceof PaddingExtensionParser);
    }

    /**
     * Test of getPreparator method, of class PaddingExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PaddingExtensionMessage()) instanceof PaddingExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class PaddingExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PaddingExtensionMessage()) instanceof PaddingExtensionSerializer);
    }

}
