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

import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import org.junit.jupiter.api.Test;

public class UnknownHandshakePreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                UnknownHandshakeMessage, UnknownHandshakePreparator> {

    public UnknownHandshakePreparatorTest() {
        super(UnknownHandshakeMessage::new, UnknownHandshakePreparator::new);
    }

    /** Test of prepareHandshakeMessageContents method, of class UnknownHandshakePreparator. */
    @Test
    public void testPrepare() {
        message.setDataConfig(new byte[] {6, 6, 6});
        preparator.prepare();
        assertArrayEquals(new byte[] {6, 6, 6}, message.getData().getValue());
    }
}
