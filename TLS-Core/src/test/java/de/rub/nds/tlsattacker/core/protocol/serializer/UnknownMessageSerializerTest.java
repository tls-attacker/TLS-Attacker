/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class UnknownMessageSerializerTest {

    private UnknownMessage msg;
    private UnknownMessageSerializer serializer;

    @Before
    public void setUp() {
        msg = new UnknownMessage(Config.createConfig(), ProtocolMessageType.UNKNOWN);
        serializer = new UnknownMessageSerializer(msg, ProtocolVersion.TLS12);
    }

    /**
     * Test of serializeProtocolMessageContent method, of class UnknownSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        msg.setCompleteResultingMessage(new byte[] { 1, 2, 3 });
        assertArrayEquals(new byte[] { 1, 2, 3 }, serializer.serialize());
    }

}
