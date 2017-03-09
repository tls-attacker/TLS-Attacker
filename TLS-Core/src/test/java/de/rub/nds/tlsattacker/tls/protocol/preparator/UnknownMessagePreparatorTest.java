/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownMessagePreparatorTest {

    private TlsContext context;
    private UnknownMessage message;
    private UnknownMessagePreparator preparator;

    public UnknownMessagePreparatorTest() {
    }

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new UnknownMessage();
        this.preparator = new UnknownMessagePreparator(context, message);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * UnknownMessagePreparator.
     */
    @Test
    public void testPrepare() {
        message.setDataConfig(new byte[] { 6, 6, 6 });
        preparator.prepare();
        assertArrayEquals(new byte[] { 6, 6, 6 }, message.getCompleteResultingMessage().getValue());
    }

}
