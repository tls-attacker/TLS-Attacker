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
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class UnknownSerializerTest {

    private UnknownMessage msg;
    private UnknownSerializer serializer;

    @Before
    public void setUp() {
        msg = new UnknownMessage();
        serializer = new UnknownSerializer(msg, ProtocolVersion.TLS12);
    }

    /**
     * Test of serializeProtocolMessageContent method, of class
     * UnknownSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        msg.setCompleteResultingMessage(new byte[] { 1, 2, 3 });
        assertArrayEquals(new byte[] { 1, 2, 3 }, serializer.serialize());
    }

}
