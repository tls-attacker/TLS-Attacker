/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ServerNamePairPreparatorTest {

    private ServerNamePair pair;
    private ServerNamePairPreparator preparator;
    private final byte[] serverName = new byte[] {0x01, 0x02};
    private final byte serverNameType = 1;

    @BeforeEach
    public void setUp() {
        TlsContext context = new TlsContext();
        pair = new ServerNamePair(serverNameType, serverName);
        preparator = new ServerNamePairPreparator(context.getChooser(), pair);
    }

    /** Test of prepare method, of class ServerNamePairPreparator. */
    @Test
    public void testPrepare() {
        preparator.prepare();

        assertArrayEquals(serverName, pair.getServerName().getValue());
        assertEquals(serverNameType, pair.getServerNameType().getValue());
        assertEquals(2, pair.getServerNameLength().getValue());
    }
}
