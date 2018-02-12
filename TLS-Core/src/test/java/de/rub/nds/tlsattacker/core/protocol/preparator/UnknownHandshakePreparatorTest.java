/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class UnknownHandshakePreparatorTest {

    private TlsContext context;
    private UnknownHandshakeMessage message;
    private UnknownHandshakePreparator preparator;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new UnknownHandshakeMessage();
        this.preparator = new UnknownHandshakePreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * UnknownHandshakePreparator.
     */
    @Test
    public void testPrepare() {
        message.setDataConfig(new byte[] { 6, 6, 6 });
        preparator.prepare();
        assertArrayEquals(new byte[] { 6, 6, 6 }, message.getData().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
