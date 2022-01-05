/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.JCommander.Builder;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.attacks.config.*;
import de.rub.nds.tlsattacker.attacks.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsattacker.attacks.impl.*;
import de.rub.nds.tlsattacker.attacks.impl.drown.GeneralDrownAttacker;
import de.rub.nds.tlsattacker.attacks.impl.drown.SpecialDrownAttacker;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     * @param args
     */
    public static void main(String[] args) {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        Builder builder = JCommander.newBuilder().addObject(generalDelegate);

        BleichenbacherCommandConfig bleichenbacherTest = new BleichenbacherCommandConfig(generalDelegate);
        builder.addCommand(BleichenbacherCommandConfig.ATTACK_COMMAND, bleichenbacherTest);

        PskBruteForcerAttackServerCommandConfig pskBruteForcerAttackServerTest =
            new PskBruteForcerAttackServerCommandConfig(generalDelegate);
        builder.addCommand(PskBruteForcerAttackServerCommandConfig.ATTACK_COMMAND, pskBruteForcerAttackServerTest);

        PskBruteForcerAttackClientCommandConfig pskBruteForcerAttackClientTest =
            new PskBruteForcerAttackClientCommandConfig(generalDelegate);
        builder.addCommand(PskBruteForcerAttackClientCommandConfig.ATTACK_COMMAND, pskBruteForcerAttackClientTest);

        InvalidCurveAttackConfig ellipticTest = new InvalidCurveAttackConfig(generalDelegate);
        builder.addCommand(InvalidCurveAttackConfig.ATTACK_COMMAND, ellipticTest);

        HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig(generalDelegate);
        builder.addCommand(HeartbleedCommandConfig.ATTACK_COMMAND, heartbleed);

        Lucky13CommandConfig lucky13 = new Lucky13CommandConfig(generalDelegate);
        builder.addCommand(Lucky13CommandConfig.ATTACK_COMMAND, lucky13);

        PaddingOracleCommandConfig paddingOracle = new PaddingOracleCommandConfig(generalDelegate);
        builder.addCommand(PaddingOracleCommandConfig.ATTACK_COMMAND, paddingOracle);

        TLSPoodleCommandConfig tlsPoodle = new TLSPoodleCommandConfig(generalDelegate);
        builder.addCommand(TLSPoodleCommandConfig.ATTACK_COMMAND, tlsPoodle);

        Cve20162107CommandConfig cve20162107 = new Cve20162107CommandConfig(generalDelegate);
        builder.addCommand(Cve20162107CommandConfig.ATTACK_COMMAND, cve20162107);

        EarlyCCSCommandConfig earlyCCS = new EarlyCCSCommandConfig(generalDelegate);
        builder.addCommand(EarlyCCSCommandConfig.ATTACK_COMMAND, earlyCCS);

        EarlyFinishedCommandConfig earlyFin = new EarlyFinishedCommandConfig(generalDelegate);
        builder.addCommand(EarlyFinishedCommandConfig.ATTACK_COMMAND, earlyFin);

        PoodleCommandConfig poodle = new PoodleCommandConfig(generalDelegate);
        builder.addCommand(PoodleCommandConfig.ATTACK_COMMAND, poodle);

        SimpleMitmProxyCommandConfig simpleMITMProxy = new SimpleMitmProxyCommandConfig(generalDelegate);
        builder.addCommand(SimpleMitmProxyCommandConfig.ATTACK_COMMAND, simpleMITMProxy);

        GeneralDrownCommandConfig generalDrownConfig = new GeneralDrownCommandConfig(generalDelegate);
        builder.addCommand(GeneralDrownCommandConfig.COMMAND, generalDrownConfig);

        SpecialDrownCommandConfig specialDrownConfig = new SpecialDrownCommandConfig(generalDelegate);
        builder.addCommand(SpecialDrownCommandConfig.COMMAND, specialDrownConfig);

        JCommander jc = builder.build();

        try {
            jc.parse(args);
        } catch (ParameterException ex) {
            String parsedCommand = ex.getJCommander().getParsedCommand();
            if (parsedCommand != null) {
                ex.getJCommander().getUsageFormatter().usage(parsedCommand);
            } else {
                ex.usage();
            }
            return;
        }

        if (jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }

        if (generalDelegate.isHelp()) {
            jc.getUsageFormatter().usage(jc.getParsedCommand());
            return;
        }

        Attacker<? extends TLSDelegateConfig> attacker = null;

        switch (jc.getParsedCommand()) {
            case BleichenbacherCommandConfig.ATTACK_COMMAND:
                attacker = new BleichenbacherAttacker(bleichenbacherTest, bleichenbacherTest.createConfig());
                break;
            case InvalidCurveAttackConfig.ATTACK_COMMAND:
                attacker = new InvalidCurveAttacker(ellipticTest, ellipticTest.createConfig());
                break;
            case HeartbleedCommandConfig.ATTACK_COMMAND:
                attacker = new HeartbleedAttacker(heartbleed, heartbleed.createConfig());
                break;
            case Lucky13CommandConfig.ATTACK_COMMAND:
                attacker = new Lucky13Attacker(lucky13, lucky13.createConfig());
                break;
            case TLSPoodleCommandConfig.ATTACK_COMMAND:
                attacker = new TLSPoodleAttacker(tlsPoodle, tlsPoodle.createConfig());
                break;
            case PaddingOracleCommandConfig.ATTACK_COMMAND:
                attacker = new PaddingOracleAttacker(paddingOracle, paddingOracle.createConfig());
                break;
            case Cve20162107CommandConfig.ATTACK_COMMAND:
                attacker = new Cve20162107Attacker(cve20162107, cve20162107.createConfig());
                break;
            case EarlyCCSCommandConfig.ATTACK_COMMAND:
                attacker = new EarlyCCSAttacker(earlyCCS, earlyCCS.createConfig());
                break;
            case EarlyFinishedCommandConfig.ATTACK_COMMAND:
                attacker = new EarlyFinishedAttacker(earlyFin, earlyFin.createConfig());
                break;
            case PoodleCommandConfig.ATTACK_COMMAND:
                attacker = new PoodleAttacker(poodle, poodle.createConfig());
                break;
            case SimpleMitmProxyCommandConfig.ATTACK_COMMAND:
                attacker = new SimpleMitmProxy(simpleMITMProxy, simpleMITMProxy.createConfig());
                break;
            case PskBruteForcerAttackClientCommandConfig.ATTACK_COMMAND:
                attacker = new PskBruteForcerAttackClient(pskBruteForcerAttackClientTest,
                    pskBruteForcerAttackClientTest.createConfig());
                break;
            case PskBruteForcerAttackServerCommandConfig.ATTACK_COMMAND:
                attacker = new PskBruteForcerAttackServer(pskBruteForcerAttackServerTest,
                    pskBruteForcerAttackServerTest.createConfig());
                break;
            case GeneralDrownCommandConfig.COMMAND:
                attacker = new GeneralDrownAttacker(generalDrownConfig, generalDrownConfig.createConfig());
                break;
            case SpecialDrownCommandConfig.COMMAND:
                attacker = new SpecialDrownAttacker(specialDrownConfig, specialDrownConfig.createConfig());
                break;
            default:
                break;
        }

        if (attacker == null) {
            throw new ConfigurationException("Command not found");
        }

        if (attacker.getConfig().isExecuteAttack()) {
            attacker.attack();
        } else {
            try {
                Boolean result = attacker.checkVulnerability();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:" + result.toString());
                } else if (Objects.equals(result, Boolean.FALSE)) {
                    CONSOLE.info("Vulnerable:" + result.toString());
                } else {
                    CONSOLE.warn("Vulnerable: Uncertain");
                }
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
    }
}
