/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class UnknownPreparatorTest {

    private TlsContext context;
    private UnknownMessage message;
    private UnknownPreparator preparator;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new UnknownMessage();
        this.preparator = new UnknownPreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * UnknownPreparator.
     */
    @Test
    public void testPrepare() {
        message.setDataConfig(new byte[] { 6, 6, 6 });
        preparator.prepare();
        assertArrayEquals(new byte[] { 6, 6, 6 }, message.getCompleteResultingMessage().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
