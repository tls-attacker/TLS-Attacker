/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class ServerNamePairPreparatorTest {

    private TlsContext context;
    private ServerNamePair pair;
    private ServerNamePairPreparator preparator;
    private final byte[] serverName = new byte[] { 0x01, 0x02 };
    private final byte serverNameType = 1;
    private final int serverNameLength = 2;

    @Before
    public void setUp() {
        context = new TlsContext();
        pair = new ServerNamePair();
        pair.setServerNameConfig(serverName);
        pair.setServerNameTypeConfig(serverNameType);
        preparator = new ServerNamePairPreparator(context.getChooser(), pair);
    }

    /**
     * Test of prepare method, of class ServerNamePairPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();

        assertArrayEquals(serverName, pair.getServerName().getValue());
        assertEquals(serverNameType, (long) pair.getServerNameType().getValue());
        assertEquals(serverNameLength, (long) pair.getServerNameLength().getValue());
    }

}
