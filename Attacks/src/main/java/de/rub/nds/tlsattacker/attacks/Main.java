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
package de.rub.nds.tlsattacker.attacks;

import de.rub.nds.tlsattacker.tls.Attacker;
import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherTestCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.EllipticCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.EllipticCurveAttackTestCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.WinshockCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttackTest;
import de.rub.nds.tlsattacker.attacks.impl.EarlyCCSAttack;
import de.rub.nds.tlsattacker.attacks.impl.EllipticCurveAttack;
import de.rub.nds.tlsattacker.attacks.impl.EllipticCurveAttackTest;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttack;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttack;
import de.rub.nds.tlsattacker.attacks.impl.WinshockAttack;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
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

	BleichenbacherTestCommandConfig bleichenbacherTest = new BleichenbacherTestCommandConfig();
	jc.addCommand(BleichenbacherTestCommandConfig.ATTACK_COMMAND, bleichenbacherTest);
	EarlyCCSCommandConfig earlyCCS = new EarlyCCSCommandConfig();
	jc.addCommand(EarlyCCSCommandConfig.ATTACK_COMMAND, earlyCCS);
	EllipticCurveAttackTestCommandConfig ellipticTest = new EllipticCurveAttackTestCommandConfig();
	jc.addCommand(EllipticCurveAttackTestCommandConfig.ATTACK_COMMAND, ellipticTest);
	EllipticCurveAttackCommandConfig elliptic = new EllipticCurveAttackCommandConfig();
	jc.addCommand(EllipticCurveAttackCommandConfig.ATTACK_COMMAND, elliptic);
	HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig();
	jc.addCommand(HeartbleedCommandConfig.ATTACK_COMMAND, heartbleed);
	PoodleCommandConfig poodle = new PoodleCommandConfig();
	jc.addCommand(PoodleCommandConfig.ATTACK_COMMAND, poodle);
	WinshockCommandConfig winshock = new WinshockCommandConfig();
	jc.addCommand(WinshockCommandConfig.ATTACK_COMMAND, winshock);

	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	Attacker attacker;
	switch (jc.getParsedCommand()) {
	    case BleichenbacherTestCommandConfig.ATTACK_COMMAND:
		attacker = new BleichenbacherAttackTest(bleichenbacherTest);
		break;
	    case EarlyCCSCommandConfig.ATTACK_COMMAND:
		attacker = new EarlyCCSAttack(earlyCCS);
		break;
	    case EllipticCurveAttackTestCommandConfig.ATTACK_COMMAND:
		attacker = new EllipticCurveAttackTest(ellipticTest);
		break;
	    case EllipticCurveAttackCommandConfig.ATTACK_COMMAND:
		attacker = new EllipticCurveAttack(elliptic);
		break;
	    case HeartbleedCommandConfig.ATTACK_COMMAND:
		attacker = new HeartbleedAttack(heartbleed);
		break;
	    case PoodleCommandConfig.ATTACK_COMMAND:
		attacker = new PoodleAttack(poodle);
		break;
	    case WinshockCommandConfig.ATTACK_COMMAND:
		attacker = new WinshockAttack(winshock);
		break;
	    default:
		throw new ConfigurationException("No command found");
	}
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initializeGeneralConfig(generalConfig);

	if (configHandler.printHelpForCommand(jc, attacker.getConfig())) {
	    return;
	}

	attacker.executeAttack(configHandler);
    }
}
