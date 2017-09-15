/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.layer;

import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.tests.IntegrationTests;
import java.util.Random;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TlsRecordLayerIT {

    private TlsRecordLayer layer;

    public TlsRecordLayerIT() {
    }

    @Before
    public void setUp() {
        layer = new TlsRecordLayer(new TlsContext(Config.createConfig()));
    }

    /**
     * Test of parseRecords method, of class TlsRecordLayer.
     */
    @Test
    @Category(IntegrationTests.class)
    public void testParseRecords() {
        Random r = RandomHelper.getRandom();
        for (int i = 0; i < 1000; i++) {
            byte[] data = new byte[r.nextInt(1000)];
            r.nextBytes(data);
            layer.parseRecordsSoftly(data);
        }
    }
}
