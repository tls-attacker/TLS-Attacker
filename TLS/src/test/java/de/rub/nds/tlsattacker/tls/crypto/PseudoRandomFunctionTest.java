/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import java.util.Random;
import mockit.Mocked;
import mockit.NonStrictExpectations;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class PseudoRandomFunctionTest {

    public PseudoRandomFunctionTest() {
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     * 
     * @param mockedTlsContext
     * @param mockedParameters
     */
    @Test
    public void testComputeForTls12(@Mocked final TlsContext mockedTlsContext,
	    @Mocked final SecurityParameters mockedParameters) {
	// Record expectations if/as needed:
	new NonStrictExpectations() {
	    {
		mockedTlsContext.getServerVersion();
		result = ProtocolVersion.TLSv12;
	    }
	    {
		mockedTlsContext.getSecurityParameters();
		result = mockedParameters;
	    }
	    {
		mockedParameters.getPrfAlgorithm();
		result = 1;
	    }
	};

	byte[] secret = new byte[48];
	String label = "master secret";
	byte[] seed = new byte[60];
	Random r = new Random();
	r.nextBytes(seed);
	int size = 48;

	byte[] result1 = TlsUtils.PRF(mockedTlsContext, secret, label, seed, size);
	byte[] result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_SHA256, secret, label, seed, size);

	assertArrayEquals(result1, result2);

	new NonStrictExpectations() {
	    {
		mockedParameters.getPrfAlgorithm();
		result = 2;
	    }
	};

	result1 = TlsUtils.PRF(mockedTlsContext, secret, label, seed, size);
	result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_SHA384, secret, label, seed, size);

	assertArrayEquals(result1, result2);
    }

    /**
     * Test of compute method, of class PseudoRandomFunction.
     */
    @Test
    public void testComputeForTls11() {
	byte[] secret = new byte[48];
	String label = "master secret";
	byte[] seed = new byte[60];
	Random r = new Random();
	r.nextBytes(seed);
	int size = 48;

	byte[] result1 = TlsUtils.PRF_legacy(secret, label, seed, size);

	byte[] result2 = PseudoRandomFunction.compute(PRFAlgorithm.TLS_PRF_LEGACY, secret, label, seed, size);

	assertArrayEquals(result1, result2);
    }
}
