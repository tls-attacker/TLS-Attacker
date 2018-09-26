/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import java.util.List;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 *
 *
 */
public class ICEPointReaderTest {

    /**
     * Test of readPoints method, of class ICEPointReader.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testReadPoints() throws Exception {
        String namedCurve = "secp192r1";
        List<ICEPoint> result = ICEPointReader.readPoints(namedCurve);

        assertEquals(5, result.get(0).getOrder());
    }

}
