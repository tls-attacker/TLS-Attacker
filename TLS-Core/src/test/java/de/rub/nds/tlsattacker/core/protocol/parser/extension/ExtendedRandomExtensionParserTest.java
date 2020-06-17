package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import org.junit.After;
import org.junit.Before;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class ExtendedRandomExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData(){
        return Arrays.asList(new Object[][]{{ExtensionType.EXTENDED_RANDOM,0,new byte[0],
                ArrayConverter.hexStringToByteArray("00280000"),0} });
    }


    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] extendedRandom;
    private final byte[] exptectedBytes;
    private final int startParsing;
    private ExtendedRandomExtensionParser parser;
    private ExtendedRandomExtensionMessage message;

    /**
     * Constructor for parameterized setup.
     *
     * @param extensionType
     * @param extensionLength
     * @param extendedRandom
     * @param expectedBytes
     * @param startParsing
     */
    public ExtendedRandomExtensionParserTest(ExtensionType extensionType, int extensionLength, byte[] extendedRandom,
                                             byte[] expectedBytes, int startParsing){
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extendedRandom = extendedRandom;
        this.exptectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Before
    public void setUp(){
        parser = new ExtendedRandomExtensionParser(startParsing, exptectedBytes);
    }

    @Test
    public void testParseExtensionMessageContent(){
        message = parser.parse();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertArrayEquals(extendedRandom, message.getExtendedRandom().getValue());

    }



}
