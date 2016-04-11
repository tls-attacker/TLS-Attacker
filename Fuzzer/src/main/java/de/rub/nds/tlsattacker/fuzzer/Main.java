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
package de.rub.nds.tlsattacker.fuzzer;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.fuzzer.config.MultiFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.impl.MultiFuzzer;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Main {

    public static void main(String[] args) throws Exception {

	// ECC does not work properly in the NSS provider
	Security.removeProvider("SunPKCS11-NSS");
	Security.addProvider(new BouncyCastleProvider());

	GeneralConfig generalConfig = new GeneralConfig();
	JCommander jc = new JCommander(generalConfig);

	MultiFuzzerConfig cmconfig = new MultiFuzzerConfig();
	jc.addCommand(MultiFuzzerConfig.ATTACK_COMMAND, cmconfig);

	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	switch (jc.getParsedCommand()) {
	    case MultiFuzzerConfig.ATTACK_COMMAND:
		startCleverMultiFuzzer(cmconfig, generalConfig, jc);
		break;
	    default:
		throw new ConfigurationException("No command found");
	}

    }

    private static void startCleverMultiFuzzer(MultiFuzzerConfig fuzzerConfig, GeneralConfig generalConfig,
	    JCommander jc) {
	MultiFuzzer fuzzer = new MultiFuzzer(fuzzerConfig, generalConfig);
	if (fuzzerConfig.isHelp()) {
	    jc.usage(MultiFuzzerConfig.ATTACK_COMMAND);
	    return;
	}
	fuzzer.startFuzzer();
    }

}
