package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedRandomExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtendedRandomExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

public class ExtendedRandomExtensionHandlerTest {
    private static final int EXTENSION_LENGTH = 0;
    private static final byte[] EXTENDED_RANDOM = new byte[] { 0x00, 0x01};

    private TlsContext context;
    private ExtendedRandomExtensionHandler handler;

    @Before
    public void setUp(){
        context = new TlsContext();
        handler = new ExtendedRandomExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        ExtendedRandomExtensionMessage message = new ExtendedRandomExtensionMessage();
        message.setExtendedRandom(EXTENDED_RANDOM);
        message.setExtensionLength(EXTENSION_LENGTH);

        handler.adjustTLSContext(message);

        if(context.getTalkingConnectionEndType().equals(ConnectionEndType.CLIENT)){
            assertArrayEquals(EXTENDED_RANDOM, context.getClientExtendedRandom());
        }
        if(context.getTalkingConnectionEndType().equals(ConnectionEndType.SERVER)){
            assertArrayEquals(EXTENDED_RANDOM, context.getServerExtendedRandom());
        }

    }

    @Test
    public void testGetParser(){
        assertTrue(handler.getParser(new byte[0], 0) instanceof ExtendedRandomExtensionParser);
    }

    @Test
    public void testGetPreparator(){
        assertTrue(handler.getPreparator(new ExtendedRandomExtensionMessage()) instanceof ExtendedRandomExtensionPreparator);
    }

    @Test
    public void testGetSerializer(){
        assertTrue(handler.getSerializer(new ExtendedRandomExtensionMessage()) instanceof ExtendedRandomExtensionSerializer);
    }

}
