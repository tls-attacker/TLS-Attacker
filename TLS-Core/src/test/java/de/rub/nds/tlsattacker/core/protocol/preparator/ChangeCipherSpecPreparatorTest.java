/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import org.junit.jupiter.api.Test;

public class ChangeCipherSpecPreparatorTest
    extends AbstractTlsMessagePreparatorTest<ChangeCipherSpecMessage, ChangeCipherSpecPreparator> {

    public ChangeCipherSpecPreparatorTest() {
        super(ChangeCipherSpecMessage::new, ChangeCipherSpecMessage::new, ChangeCipherSpecPreparator::new);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class ChangeCipherSpecPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();
        assertEquals(1, message.getCcsProtocolType().getValue()[0]);
    }
}
