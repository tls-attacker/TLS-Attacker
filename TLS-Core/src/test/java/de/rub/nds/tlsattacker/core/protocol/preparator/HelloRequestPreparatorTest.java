/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import org.junit.jupiter.api.Test;

public class HelloRequestPreparatorTest
        extends AbstractProtocolMessagePreparatorTest<HelloRequestMessage, HelloRequestPreparator> {

    public HelloRequestPreparatorTest() {
        super(HelloRequestMessage::new, HelloRequestPreparator::new);
    }

    /** Test of prepareHandshakeMessageContents method, of class HelloRequestPreparator. */
    @Test
    @Override
    public void testPrepare() {
        assertDoesNotThrow(preparator::prepare);
        // Just check that preparation did not throw an exception
    }
}
