/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class KeySharePairPreparatorTest {

    private KeyShareEntryPreparator preparator;
    private KeyShareEntry entry;
    private TlsContext context;

    public KeySharePairPreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        entry = new KeyShareEntry(NamedGroup.ECDH_X25519, new BigInteger(
                "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF", 16));
        preparator = new KeyShareEntryPreparator(context.getChooser(), entry);

    }

    /**
     * Test of prepare method, of class KeyShareEntryPreparator.
     */
    @Test
    public void testPrepare() {
        preparator.prepare();
        assertArrayEquals(entry.getPublicKey().getValue(),
                ArrayConverter.hexStringToByteArray("2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"));
        assertTrue(entry.getPublicKeyLength().getValue() == 32);
        assertArrayEquals(entry.getGroup().getValue(), ArrayConverter.hexStringToByteArray("001D"));

    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

}
