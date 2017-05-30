/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.preparator.RetransmitMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RetransmitMessagePreparatorTest {

    private RetransmitMessage message;
    private TlsContext context;
    private RetransmitMessagePreparator preparator;

    public RetransmitMessagePreparatorTest() {
    }

    @Before
    public void setUp() {
        message = new RetransmitMessage(new byte[] { 0, 1, 2, 3 });
        context = new TlsContext();
        preparator = new RetransmitMessagePreparator(context, message);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * RetransmitMessagePreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, message.getCompleteResultingMessage().getValue());
    }

}
