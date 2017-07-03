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
import de.rub.nds.tlsattacker.core.protocol.message.RetransmitMessage;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RetransmitMessageSerializerTest {

    private RetransmitMessageSerializer serializer;
    private RetransmitMessage msg;

    @Before
    public void setUp() {
        msg = new RetransmitMessage();
        msg.setCompleteResultingMessage(new byte[] { 6, 6, 6 });
        serializer = new RetransmitMessageSerializer(msg, ProtocolVersion.TLS12);
    }

    /**
     * Test of serializeProtocolMessageContent method, of class
     * RetransmitMessageSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        assertArrayEquals(new byte[] { 6, 6, 6 }, serializer.serialize());
    }
}
