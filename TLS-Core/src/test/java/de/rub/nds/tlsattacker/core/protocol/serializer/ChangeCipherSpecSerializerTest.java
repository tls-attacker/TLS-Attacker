/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParserTest;
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
public class ChangeCipherSpecSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ChangeCipherSpecParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private byte ccsType;

    public ChangeCipherSpecSerializerTest(byte[] message, int start, byte[] expectedPart, byte ccsType) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.ccsType = ccsType;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class
     * ChangeCipherSpecSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        ChangeCipherSpecMessage msg = new ChangeCipherSpecMessage();
        msg.setCcsProtocolType(ccsType);
        msg.setCompleteResultingMessage(expectedPart);
        ChangeCipherSpecSerializer serializer = new ChangeCipherSpecSerializer(msg, ProtocolVersion.TLS12);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
