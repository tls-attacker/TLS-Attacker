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
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.TestPkcs1Oracle;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.StdPlainPkcs1Oracle;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.Assert;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class BleichenbacherOracleTest {

    @Test
    public final void testJSSEOracle() throws Exception {

	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	keyPairGenerator.initialize(1024);
	KeyPair keyPair = keyPairGenerator.genKeyPair();
	Pkcs1Oracle oracle = new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.JSSE, 128);

	byte[] msg = new byte[127];
	for (int i = 0; i < msg.length; i++) {
	    msg[i] = 0x01;
	}
	// start with 0x02, no 0x00 byte given
	msg[0] = 0x02;

	Assert.assertFalse(oracle.checkPKCSConformity(msg));

	// set the second last byte to 0x00
	msg[msg.length - 2] = 0x00;
	Assert.assertTrue(oracle.checkPKCSConformity(msg));

	// insert an extra 0x00 byte in the middle
	msg[20] = 0x00;
	Assert.assertFalse(oracle.checkPKCSConformity(msg));
    }

    @Test
    public final void testXMLENCOracle() throws Exception {

	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	keyPairGenerator.initialize(1024);
	KeyPair keyPair = keyPairGenerator.genKeyPair();
	Pkcs1Oracle oracle = new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.XMLENC, 128);

	byte[] msg = new byte[127];
	for (int i = 0; i < msg.length; i++) {
	    msg[i] = 0x01;
	}
	// start with 0x02, no 0x00 byte given
	msg[0] = 0x02;

	Assert.assertFalse(oracle.checkPKCSConformity(msg));

	// set the 17th byte from behind to 0x00
	msg[msg.length - 17] = 0x00;
	Assert.assertTrue(oracle.checkPKCSConformity(msg));

	// set the 25th byte from behind to 0x00
	msg[msg.length - 25] = 0x00;
	Assert.assertTrue(oracle.checkPKCSConformity(msg));

	// set the 33th byte from behind to 0x00
	msg[msg.length - 33] = 0x00;
	Assert.assertTrue(oracle.checkPKCSConformity(msg));

	msg[34] = 0x00;
	Assert.assertFalse(oracle.checkPKCSConformity(msg));

	// insert an extra 0x00 byte in the middle
	msg[50] = 0x00;
	Assert.assertFalse(oracle.checkPKCSConformity(msg));
    }
}
