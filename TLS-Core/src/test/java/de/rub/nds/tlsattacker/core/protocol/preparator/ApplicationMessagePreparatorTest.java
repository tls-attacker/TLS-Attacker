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

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import org.junit.jupiter.api.Test;

public class ApplicationMessagePreparatorTest
    extends AbstractTlsMessagePreparatorTest<ApplicationMessage, ApplicationMessagePreparator> {

    public ApplicationMessagePreparatorTest() {
        super(ApplicationMessage::new, ApplicationMessage::new, ApplicationMessagePreparator::new);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class ApplicationMessagePreparator.
     */
    @Test
    @Override
    public void testPrepare() {
        context.getConfig().setDefaultApplicationMessageData("1234");
        preparator.prepare();
        assertArrayEquals(message.getData().getValue(), "1234".getBytes());
    }
}
