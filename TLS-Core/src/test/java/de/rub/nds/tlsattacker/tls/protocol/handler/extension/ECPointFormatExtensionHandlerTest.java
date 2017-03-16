/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ECPointFormatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.ECPointFormatExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.ECPointFormatExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ECPointFormatExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECPointFormatExtensionHandlerTest {

    private ECPointFormatExtensionHandler handler;
    private TlsContext context;

    public ECPointFormatExtensionHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ECPointFormatExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class ECPointFormatExtensionHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        msg.setPointFormats(new byte[] { 0, 1 });
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientPointFormatsList().size() == 2);
        assertTrue(context.getClientPointFormatsList().contains(ECPointFormat.UNCOMPRESSED));
        assertTrue(context.getClientPointFormatsList().contains(ECPointFormat.ANSIX962_COMPRESSED_PRIME));
    }

    public void testUnadjustableMessage() {
        ECPointFormatExtensionMessage msg = new ECPointFormatExtensionMessage();
        msg.setPointFormats(new byte[] { 5 });
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientPointFormatsList().isEmpty());
    }

    /**
     * Test of getParser method, of class ECPointFormatExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 123 }, 0) instanceof ECPointFormatExtensionParser);
    }

    /**
     * Test of getPreparator method, of class ECPointFormatExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ECPointFormatExtensionMessage()) instanceof ECPointFormatExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class ECPointFormatExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ECPointFormatExtensionMessage()) instanceof ECPointFormatExtensionSerializer);
    }

}
