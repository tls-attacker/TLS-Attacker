/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class MaxFragmentLengthExtensionParserTest {

    
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { });//TODO collect a real maxfragmentlength extension
    }

    private byte[] extension;
    private int start;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private byte[] maxFragmentLength;

    public MaxFragmentLengthExtensionParserTest(byte[] extension, int start, byte[] completeExtension, ExtensionType type, int extensionLength, byte[] maxFragmentLength) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.maxFragmentLength = maxFragmentLength;
    }
    
    /**
     * Test of parseExtensionMessageContent method, of class
     * MaxFragmentLengthExtensionParser.
     */
    @Test
    public void testParseExtensionMessageContent() {
        MaxFragmentLengthExtensionParser parser = new MaxFragmentLengthExtensionParser(start, extension);
        MaxFragmentLengthExtensionMessage msg = parser.parse();
        assertArrayEquals(msg.getExtensionBytes().getValue(), completeExtension);
        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertTrue(extensionLength == msg.getExtensionLength().getValue());
        assertTrue(maxFragmentLength == msg.getMaxFragmentLength().getValue());
    }
}
