/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

public class HelloRequestPreparatorTest {

    private TlsContext context;
    private HelloRequestMessage message;
    private HelloRequestPreparator preparator;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new HelloRequestMessage();
        this.preparator = new HelloRequestPreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class HelloRequestPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();
        // Just check that preparation did not throw an exception
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
