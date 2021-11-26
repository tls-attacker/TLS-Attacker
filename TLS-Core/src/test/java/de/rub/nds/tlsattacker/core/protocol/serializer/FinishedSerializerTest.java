/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedMessageParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class FinishedSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return FinishedMessageParserTest.generateData();
    }

    private final byte[] expectedPart;
    private final byte[] verifyData;

    private final ProtocolVersion version;

    public FinishedSerializerTest(byte[] expectedPart, byte[] verifyData, ProtocolVersion version) {
        this.expectedPart = expectedPart;
        this.verifyData = verifyData;
        this.version = version;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class FinishedSerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        FinishedMessage msg = new FinishedMessage();
        msg.setVerifyData(verifyData);
        msg.setCompleteResultingMessage(expectedPart);
        FinishedSerializer serializer = new FinishedSerializer(msg, version);
        assertArrayEquals(expectedPart, serializer.serializeProtocolMessageContent());
    }

}
