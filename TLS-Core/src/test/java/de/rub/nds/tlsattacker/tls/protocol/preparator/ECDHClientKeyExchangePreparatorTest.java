/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHClientKeyExchangePreparatorTest {

    private TlsContext context;
    private ECDHClientKeyExchangeMessage message;
    private ECDHClientKeyExchangePreparator preparator;

    public ECDHClientKeyExchangePreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new ECDHClientKeyExchangeMessage();
        preparator = new ECDHClientKeyExchangePreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * ECDHClientKeyExchangePreparator.
     */
    @Test
    public void testPrepare() {
        // TODO
    }

}
