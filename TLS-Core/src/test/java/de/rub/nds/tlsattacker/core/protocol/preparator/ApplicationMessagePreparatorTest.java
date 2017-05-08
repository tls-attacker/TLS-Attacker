/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ApplicationMessagePreparatorTest {

    private ApplicationMessage message;
    private ApplicationMessagePreparator preparator;
    private TlsContext context;

    public ApplicationMessagePreparatorTest() {
    }

    @Before
    public void setUp() {
        message = new ApplicationMessage();
        context = new TlsContext();
        preparator = new ApplicationMessagePreparator(context, message);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * ApplicationMessagePreparator.
     */
    @Test
    public void testPrepare() {
        context.getConfig().setDefaultApplicationMessageData("1234");
        preparator.prepare();
        assertArrayEquals(message.getData().getValue(), "1234".getBytes());
    }
}
