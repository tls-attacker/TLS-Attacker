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
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class KeySharePairPreparatorTest {

    private KeySharePairPreparator preparator;
    private KeySharePair pair;
    private TlsContext context;

    public KeySharePairPreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        pair = new KeySharePair();
        preparator = new KeySharePairPreparator(context.getChooser(), pair);

    }

    /**
     * Test of prepare method, of class KeySharePairPreparator.
     */
    @Test
    public void testPrepare() {
        pair.setKeyShareTypeConfig(ArrayConverter.hexStringToByteArray("001D"));
        pair.setKeyShareConfig(ArrayConverter
                .hexStringToByteArray("2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"));
        preparator.prepare();
        assertArrayEquals(pair.getKeyShare().getValue(),
                ArrayConverter.hexStringToByteArray("2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"));
        assertTrue(pair.getKeyShareLength().getValue() == 32);
        assertArrayEquals(pair.getKeyShareType().getValue(), ArrayConverter.hexStringToByteArray("001D"));

    }

}
