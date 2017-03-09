/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HelloRequestPreparatorTest {

    private TlsContext context;
    private HelloRequestMessage message;
    private HelloRequestPreparator preparator;

    public HelloRequestPreparatorTest() {
    }

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new HelloRequestMessage();
        this.preparator = new HelloRequestPreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * HelloRequestPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();
        // Just check that preparation did not throw an exception
    }

}
