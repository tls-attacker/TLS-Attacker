/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCipherSpecPreparatorTest {

    private ChangeCipherSpecPreparator preparator;
    private ChangeCipherSpecMessage message;
    private TlsContext context;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new ChangeCipherSpecMessage();
        preparator = new ChangeCipherSpecPreparator(context, message);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * ChangeCipherSpecPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();
        assertTrue(message.getCcsProtocolType().getValue() == 1);
    }

}
