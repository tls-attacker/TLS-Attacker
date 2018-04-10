/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ChangeCipherSpecSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ChangeCipherSpecParserTest.generateData();
    }

    private final byte[] expectedPart;
    private final ProtocolVersion version;

    private final byte ccsType;

    public ChangeCipherSpecSerializerTest(byte[] message, byte ccsType, ProtocolVersion version) {
        this.expectedPart = message;
        this.ccsType = ccsType;
        this.version = version;
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
        ChangeCipherSpecSerializer serializer = new ChangeCipherSpecSerializer(msg, version);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
