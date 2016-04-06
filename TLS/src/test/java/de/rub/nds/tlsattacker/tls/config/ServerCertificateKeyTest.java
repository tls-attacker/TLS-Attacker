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
package de.rub.nds.tlsattacker.tls.config;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ServerCertificateKeyTest {

    public ServerCertificateKeyTest() {
    }

    /**
     * Test of getServerCertificateKey method, of class ServerCertificateKey.
     */
    @Test
    public void testGetServerCertificateKey() {
	assertEquals(ServerCertificateKey.DH,
		ServerCertificateKey.getServerCertificateKey(CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA));
	assertEquals(ServerCertificateKey.RSA,
		ServerCertificateKey.getServerCertificateKey(CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA));
	assertEquals(ServerCertificateKey.RSA,
		ServerCertificateKey.getServerCertificateKey(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA));
	assertEquals(ServerCertificateKey.EC,
		ServerCertificateKey.getServerCertificateKey(CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA));
	assertEquals(ServerCertificateKey.NONE,
		ServerCertificateKey.getServerCertificateKey(CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA));
    }

}
