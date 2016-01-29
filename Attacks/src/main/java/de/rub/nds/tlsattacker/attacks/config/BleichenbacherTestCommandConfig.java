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
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import java.util.LinkedList;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class BleichenbacherTestCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "bleichenbacher_test";

    public enum Type {
	FULL,
	FAST
    }

    @Parameter(names = "-type", description = "Type of the Bleichenbacher Test results in a different number of server test quries (FAST/FULL)")
    Type type;

    public BleichenbacherTestCommandConfig() {
	cipherSuites = new LinkedList<>();
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
	cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
	type = Type.FAST;
    }

    public Type getType() {
	return type;
    }

    public void setType(Type type) {
	this.type = type;
    }
}
