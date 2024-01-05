/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.junit.jupiter.api.Test;

public class HeartbeatMessagePreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                HeartbeatMessage, HeartbeatMessagePreparator> {

    public HeartbeatMessagePreparatorTest() {
        super(HeartbeatMessage::new, HeartbeatMessagePreparator::new);
    }

    /** Test of prepareProtocolMessageContents method, of class HeartbeatMessagePreparator. */
    @Test
    @Override
    public void testPrepare() {
        context.getConfig().setHeartbeatPayloadLength(11);
        context.getConfig().setHeartbeatPaddingLength(11);
        context.setRandom(
                new FixedSecureRandom(
                        ArrayConverter.hexStringToByteArray(
                                "F6C92DA33AF01D4FB770AA60B420BB3851D9D47ACB93")));
        preparator.prepare();
        assertEquals(
                HeartbeatMessageType.HEARTBEAT_REQUEST.getValue(),
                (byte) message.getHeartbeatMessageType().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("60B420BB3851D9D47ACB93"),
                message.getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("F6C92DA33AF01D4FB770AA"),
                message.getPayload().getValue());
        assertEquals(11, (int) message.getPayloadLength().getValue());
    }
}
