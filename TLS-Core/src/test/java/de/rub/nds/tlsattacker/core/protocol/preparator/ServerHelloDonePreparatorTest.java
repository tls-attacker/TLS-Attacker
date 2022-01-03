/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

public class ServerHelloDonePreparatorTest {

    private TlsContext context;
    private ServerHelloDoneMessage message;
    private ServerHelloDonePreparator preparator;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new ServerHelloDoneMessage();
        this.preparator = new ServerHelloDonePreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class ServerHelloDonePreparator.
     */
    @Test
    public void testPrepare() {

        // just check that prepare does not throw an exception
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
