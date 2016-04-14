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
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.DtlsPaddingOracleAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackFullCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.SniTestCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.WinshockCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttack;
import de.rub.nds.tlsattacker.attacks.impl.DtlsPaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.EarlyCCSAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttackFull;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttack;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttack;
import de.rub.nds.tlsattacker.attacks.impl.SniTest;
import de.rub.nds.tlsattacker.attacks.impl.WinshockAttack;
import de.rub.nds.tlsattacker.fuzzer.config.MultiFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.impl.MultiFuzzer;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Main {

    public static void main(String[] args) throws Exception {

	GeneralConfig generalConfig = new GeneralConfig();
	JCommander jc = new JCommander(generalConfig);

	MultiFuzzerConfig cmconfig = new MultiFuzzerConfig();
	jc.addCommand(MultiFuzzerConfig.ATTACK_COMMAND, cmconfig);

	BleichenbacherCommandConfig bleichenbacherTest = new BleichenbacherCommandConfig();
	jc.addCommand(BleichenbacherCommandConfig.ATTACK_COMMAND, bleichenbacherTest);
	DtlsPaddingOracleAttackCommandConfig dtlsPaddingOracleAttackTest = new DtlsPaddingOracleAttackCommandConfig();
	jc.addCommand(DtlsPaddingOracleAttackCommandConfig.ATTACK_COMMAND, dtlsPaddingOracleAttackTest);
//	EarlyCCSCommandConfig earlyCCS = new EarlyCCSCommandConfig();
//	jc.addCommand(EarlyCCSCommandConfig.ATTACK_COMMAND, earlyCCS);
	InvalidCurveAttackCommandConfig ellipticTest = new InvalidCurveAttackCommandConfig();
	jc.addCommand(InvalidCurveAttackCommandConfig.ATTACK_COMMAND, ellipticTest);
	InvalidCurveAttackFullCommandConfig elliptic = new InvalidCurveAttackFullCommandConfig();
	jc.addCommand(InvalidCurveAttackFullCommandConfig.ATTACK_COMMAND, elliptic);
	HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig();
	jc.addCommand(HeartbleedCommandConfig.ATTACK_COMMAND, heartbleed);
	PaddingOracleCommandConfig paddingOracle = new PaddingOracleCommandConfig();
	jc.addCommand(PaddingOracleCommandConfig.ATTACK_COMMAND, paddingOracle);
	PoodleCommandConfig poodle = new PoodleCommandConfig();
	jc.addCommand(PoodleCommandConfig.ATTACK_COMMAND, poodle);
//	SniTestCommandConfig sniTest = new SniTestCommandConfig();
//	jc.addCommand(SniTestCommandConfig.ATTACK_COMMAND, sniTest);
	WinshockCommandConfig winshock = new WinshockCommandConfig();
	jc.addCommand(WinshockCommandConfig.ATTACK_COMMAND, winshock);

	jc.parse(args);

	if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
	    jc.usage();
	    return;
	}

	Attacker attacker;
	switch (jc.getParsedCommand()) {
	    case MultiFuzzerConfig.ATTACK_COMMAND:
		startMultiFuzzer(cmconfig, generalConfig, jc);
		return;
	    case BleichenbacherCommandConfig.ATTACK_COMMAND:
		attacker = new BleichenbacherAttack(bleichenbacherTest);
		break;
//	    case EarlyCCSCommandConfig.ATTACK_COMMAND:
//		attacker = new EarlyCCSAttack(earlyCCS);
//		break;
	    case InvalidCurveAttackCommandConfig.ATTACK_COMMAND:
		attacker = new InvalidCurveAttack(ellipticTest);
		break;
	    case InvalidCurveAttackFullCommandConfig.ATTACK_COMMAND:
		attacker = new InvalidCurveAttackFull(elliptic);
		break;
	    case HeartbleedCommandConfig.ATTACK_COMMAND:
		attacker = new HeartbleedAttack(heartbleed);
		break;
	    case PoodleCommandConfig.ATTACK_COMMAND:
		attacker = new PoodleAttack(poodle);
		break;
	    case PaddingOracleCommandConfig.ATTACK_COMMAND:
		attacker = new PaddingOracleAttack(paddingOracle);
		break;
	    case WinshockCommandConfig.ATTACK_COMMAND:
		attacker = new WinshockAttack(winshock);
		break;
	    case DtlsPaddingOracleAttackCommandConfig.ATTACK_COMMAND:
		attacker = new DtlsPaddingOracleAttack(dtlsPaddingOracleAttackTest);
		break;
//	    case SniTestCommandConfig.ATTACK_COMMAND:
//		attacker = new SniTest(sniTest);
//		break;
	    default:
		throw new ConfigurationException("No command found");
	}
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);

	if (configHandler.printHelpForCommand(jc, attacker.getConfig())) {
	    return;
	}

	attacker.executeAttack(configHandler);

    }

    private static void startMultiFuzzer(MultiFuzzerConfig fuzzerConfig, GeneralConfig generalConfig, JCommander jc) {
	MultiFuzzer fuzzer = new MultiFuzzer(fuzzerConfig, generalConfig);
	if (fuzzerConfig.isHelp()) {
	    jc.usage(MultiFuzzerConfig.ATTACK_COMMAND);
	    return;
	}
	fuzzer.startFuzzer();
    }
}
