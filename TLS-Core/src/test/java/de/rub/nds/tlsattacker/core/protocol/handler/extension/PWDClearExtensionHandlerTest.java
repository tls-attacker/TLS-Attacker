package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PWDClearExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PWDClearExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDClearExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class PWDClearExtensionHandlerTest {
    private PWDClearExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PWDClearExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        PWDClearExtensionMessage message = new PWDClearExtensionMessage();
        handler.adjustTLSContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.PWD_CLEAR));
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof PWDClearExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PWDClearExtensionMessage()) instanceof PWDClearExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PWDClearExtensionMessage()) instanceof PWDClearExtensionSerializer);
    }

}