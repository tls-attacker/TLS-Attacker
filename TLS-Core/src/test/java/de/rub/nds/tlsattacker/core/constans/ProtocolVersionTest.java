/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constans;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola
 */
public class ProtocolVersionTest {

    public ProtocolVersionTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of gethighestProtocolVersion method, of class ProtocolVersion.
     */
    @Test
    public void testPrepare1() {
        List<ProtocolVersion> versions = new LinkedList<>();
        versions.add(ProtocolVersion.TLS10);
        versions.add(ProtocolVersion.TLS11);
        versions.add(ProtocolVersion.TLS12);
        versions.add(ProtocolVersion.TLS13);
        ProtocolVersion highestProtocolVersion = ProtocolVersion.gethighestProtocolVersion(versions);
        assertArrayEquals(ProtocolVersion.TLS13.getValue(), highestProtocolVersion.getValue());
    }

}
