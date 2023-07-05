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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class KeySharePairPreparatorTest {

    private KeyShareEntryPreparator preparator;
    private KeyShareEntry entry;

    @BeforeEach
    public void setUp() {
        TlsContext context = new TlsContext();
        entry =
                new KeyShareEntry(
                        NamedGroup.ECDH_X25519,
                        new BigInteger(
                                "03BD8BCA70C19F657E897E366DBE21A466E4924AF6082DBDF573827BCDDE5DEF",
                                16));
        preparator = new KeyShareEntryPreparator(context.getChooser(), entry);
    }

    /** Test of prepare method, of class KeyShareEntryPreparator. */
    @Test
    public void testPrepare() {
        preparator.prepare();
        assertArrayEquals(
                entry.getPublicKey().getValue(),
                ArrayConverter.hexStringToByteArray(
                        "2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"));
        assertEquals(32, (int) entry.getPublicKeyLength().getValue());
        assertArrayEquals(entry.getGroup().getValue(), ArrayConverter.hexStringToByteArray("001D"));
    }

    @Test
    public void testPrepareNoContext() {
        preparator.prepare();
    }
}
