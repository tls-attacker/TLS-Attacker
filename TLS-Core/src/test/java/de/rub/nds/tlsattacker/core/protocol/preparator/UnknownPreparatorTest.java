/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import org.junit.jupiter.api.Test;

public class UnknownPreparatorTest extends AbstractTlsMessagePreparatorTest<UnknownMessage, UnknownMessagePreparator> {

    public UnknownPreparatorTest() {
        super(UnknownMessage::new, UnknownMessage::new, UnknownMessagePreparator::new);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class UnknownPreparator.
     */
    @Test
    public void testPrepare() {
        message.setDataConfig(new byte[] { 6, 6, 6 });
        preparator.prepare();
        assertArrayEquals(new byte[] { 6, 6, 6 }, message.getCompleteResultingMessage().getValue());
    }
}
