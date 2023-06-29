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
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CachedObjectPreparatorTest {

    private TlsContext context;

    @BeforeEach
    public void setUp() {
        context = new TlsContext();
    }

    @Test
    public void testPreparator() {
        int hashLength = 3;
        byte cachedInfoType = 1;
        byte[] hash = new byte[] {0x01, 0x02, 0x03};

        CachedObject object = new CachedObject(cachedInfoType, hashLength, hash);
        CachedObjectPreparator preparator =
                new CachedObjectPreparator(context.getChooser(), object);

        preparator.prepare();

        assertEquals(cachedInfoType, (long) object.getCachedInformationType().getValue());
        assertEquals(hashLength, (long) object.getHashValueLength().getValue());
        assertArrayEquals(hash, object.getHashValue().getValue());
    }
}
