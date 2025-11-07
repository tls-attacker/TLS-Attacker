/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.hints;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import org.junit.jupiter.api.Test;

class RecordLayerHintTest {

    @Test
    void testEqualsWithIntegerObjects() {
        Integer epoch1 = Integer.valueOf(200);
        Integer epoch2 = Integer.valueOf(200);
        Integer sequenceNumber1 = Integer.valueOf(1000);
        Integer sequenceNumber2 = Integer.valueOf(1000);

        RecordLayerHint hint1 =
                new RecordLayerHint(ProtocolMessageType.HANDSHAKE, epoch1, sequenceNumber1);
        RecordLayerHint hint2 =
                new RecordLayerHint(ProtocolMessageType.HANDSHAKE, epoch2, sequenceNumber2);

        assertNotSame(epoch1, epoch2);
        assertNotSame(sequenceNumber1, sequenceNumber2);
        assertEquals(hint1, hint2);
    }

    @Test
    void testEqualsWithLargeIntegers() {
        RecordLayerHint hint1 =
                new RecordLayerHint(ProtocolMessageType.APPLICATION_DATA, 256, 100000);
        RecordLayerHint hint2 =
                new RecordLayerHint(ProtocolMessageType.APPLICATION_DATA, 256, 100000);

        assertEquals(hint1, hint2);
    }

    @Test
    void testEqualsWithNullValues() {
        RecordLayerHint hint1 = new RecordLayerHint(ProtocolMessageType.ALERT);
        RecordLayerHint hint2 = new RecordLayerHint(ProtocolMessageType.ALERT);

        assertEquals(hint1, hint2);
    }

    @Test
    void testNotEqualsWithDifferentTypes() {
        RecordLayerHint hint1 = new RecordLayerHint(ProtocolMessageType.HANDSHAKE);
        RecordLayerHint hint2 = new RecordLayerHint(ProtocolMessageType.APPLICATION_DATA);

        assertNotEquals(hint1, hint2);
    }

    @Test
    void testEqualsWithMessageSequence() {
        RecordLayerHint hint1 = new RecordLayerHint(ProtocolMessageType.HANDSHAKE, 1000);
        RecordLayerHint hint2 = new RecordLayerHint(ProtocolMessageType.HANDSHAKE, 1000);

        assertEquals(hint1, hint2);
    }
}
