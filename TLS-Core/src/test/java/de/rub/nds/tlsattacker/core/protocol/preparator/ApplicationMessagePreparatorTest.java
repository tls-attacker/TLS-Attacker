/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class ApplicationMessagePreparatorTest {

    private ApplicationMessage message;
    private ApplicationMessagePreparator preparator;
    private TlsContext context;

    @Before
    public void setUp() {
        message = new ApplicationMessage();
        context = new TlsContext();
        preparator = new ApplicationMessagePreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class ApplicationMessagePreparator.
     */
    @Test
    public void testPrepare() {
        context.getConfig().setDefaultApplicationMessageData("1234");
        preparator.prepare();
        assertArrayEquals(message.getData().getValue(), "1234".getBytes());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
