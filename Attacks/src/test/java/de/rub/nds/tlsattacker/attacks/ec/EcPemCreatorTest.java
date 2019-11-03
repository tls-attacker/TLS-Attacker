/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.ec;

import java.math.BigInteger;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class EcPemCreatorTest {

    @Test
    public void testConversion() throws Exception {
        BigInteger key = new BigInteger("45920025678221661724778903394380424235512150060610104911582497586860611281771");
        String curve = "secp256r1";
        String result = EcPemCreator.createPemFromPrivateEcKey(curve, key);
        assertEquals(EcPemCreator.BEGIN_EC_PRIVATE_KEY
                + "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBlhdBA2pVVpBpVqfWQLlnfZyfy1SNQtMubbhwcCFsjaw==" + "\n"
                + EcPemCreator.END_EC_PRIVATE_KEY, result);
    }
}
