/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
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
public class ChangeCipherSpecParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { new byte[] { 0x01 }, 0, new byte[] { 0x01 }, (byte) 1 },
                { new byte[] { 0x05 }, 0, new byte[] { 0x05 }, (byte) 5 } });
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private byte ccsType;

    public ChangeCipherSpecParserTest(byte[] message, int start, byte[] expectedPart, byte ccsType) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.ccsType = ccsType;
    }

    /**
     * Test of parse method, of class ChangeCipherSpecParser.
     */
    @Test
    public void testParse() {
        ChangeCipherSpecParser parser = new ChangeCipherSpecParser(start, message, ProtocolVersion.TLS12);
        ChangeCipherSpecMessage ccsMessagee = parser.parse();
        assertArrayEquals(expectedPart, ccsMessagee.getCompleteResultingMessage().getValue());
        assertTrue(ccsType == ccsMessagee.getCcsProtocolType().getValue());
    }

}
