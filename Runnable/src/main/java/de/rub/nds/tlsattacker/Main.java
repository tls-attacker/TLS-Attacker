/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.Cve20162107CommandConfig;
import de.rub.nds.tlsattacker.attacks.config.DtlsPaddingOracleAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackFullCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.Lucky13CommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.WinshockCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttack;
import de.rub.nds.tlsattacker.attacks.impl.Cve20162107;
import de.rub.nds.tlsattacker.attacks.impl.DtlsPaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttackFull;
import de.rub.nds.tlsattacker.attacks.impl.Lucky13Attack;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttack;
import de.rub.nds.tlsattacker.attacks.impl.WinshockAttack;
import de.rub.nds.tlsattacker.main.TlsClient;
import de.rub.nds.tlsattacker.testsuite.config.ServerTestSuiteConfig;
import de.rub.nds.tlsattacker.testsuite.impl.ServerTestSuite;
import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.impl.TestTLSServer;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.client.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tlsserver.ServerCommandConfig;
import de.rub.nds.tlsattacker.tlsserver.TlsServer;
import java.io.IOException;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger(Main.class);

    public static void main(String[] args) throws Exception {
        // TODO TODO TODO
        GeneralDelegate generalDelegate = new GeneralDelegate();
        JCommander jc = new JCommander(generalDelegate);

        BleichenbacherCommandConfig bleichenbacherTest = new BleichenbacherCommandConfig();
        jc.addCommand(BleichenbacherCommandConfig.ATTACK_COMMAND, bleichenbacherTest);
        DtlsPaddingOracleAttackCommandConfig dtlsPaddingOracleAttackTest = new DtlsPaddingOracleAttackCommandConfig();
        jc.addCommand(DtlsPaddingOracleAttackCommandConfig.ATTACK_COMMAND, dtlsPaddingOracleAttackTest);
        InvalidCurveAttackCommandConfig ellipticTest = new InvalidCurveAttackCommandConfig();
        jc.addCommand(InvalidCurveAttackCommandConfig.ATTACK_COMMAND, ellipticTest);
        InvalidCurveAttackFullCommandConfig elliptic = new InvalidCurveAttackFullCommandConfig();
        jc.addCommand(InvalidCurveAttackFullCommandConfig.ATTACK_COMMAND, elliptic);
        HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig();
        jc.addCommand(HeartbleedCommandConfig.ATTACK_COMMAND, heartbleed);
        Lucky13CommandConfig lucky13 = new Lucky13CommandConfig();
        jc.addCommand(Lucky13CommandConfig.ATTACK_COMMAND, lucky13);
        PaddingOracleCommandConfig paddingOracle = new PaddingOracleCommandConfig();
        jc.addCommand(PaddingOracleCommandConfig.ATTACK_COMMAND, paddingOracle);
        PoodleCommandConfig poodle = new PoodleCommandConfig();
        jc.addCommand(PoodleCommandConfig.ATTACK_COMMAND, poodle);
        Cve20162107CommandConfig cve20162107 = new Cve20162107CommandConfig();
        jc.addCommand(Cve20162107CommandConfig.ATTACK_COMMAND, cve20162107);
        WinshockCommandConfig winshock = new WinshockCommandConfig();
        jc.addCommand(WinshockCommandConfig.ATTACK_COMMAND, winshock);
        ServerCommandConfig server = new ServerCommandConfig();
        jc.addCommand(ServerCommandConfig.COMMAND, server);
        ClientCommandConfig client = new ClientCommandConfig();
        jc.addCommand(ClientCommandConfig.COMMAND, client);
        ServerTestSuiteConfig stconfig = new ServerTestSuiteConfig();
        jc.addCommand(ServerTestSuiteConfig.COMMAND, stconfig);
        TestServerConfig testServerConfig = new TestServerConfig();
        jc.addCommand(TestServerConfig.COMMAND, testServerConfig);

        jc.parse(args);

        if (generalDelegate.isHelp() || jc.getParsedCommand() == null) {
            if (jc.getParsedCommand() == null) {
                jc.usage();
            } else {
                jc.usage(jc.getParsedCommand());
            }
            return;
        }

        Attacker<? extends TLSDelegateConfig> attacker;
        switch (jc.getParsedCommand()) {
            case ServerCommandConfig.COMMAND:
                startSimpleTlsServer(server);
                return;
            case ClientCommandConfig.COMMAND:
                startSimpleTlsClient(client);
                return;
            case ServerTestSuiteConfig.COMMAND:
                ServerTestSuite st = new ServerTestSuite(stconfig);
                boolean success = st.startTests();
                if (success) {
                    System.exit(0);
                } else {
                    System.exit(1);
                }
                return;
            case TestServerConfig.COMMAND:
                TestTLSServer testTlsServer = new TestTLSServer(testServerConfig);
                success = testTlsServer.startTests();
                if (success) {
                    System.exit(0);
                } else {
                    System.exit(1);
                }
                return;
            case BleichenbacherCommandConfig.ATTACK_COMMAND:
                attacker = new BleichenbacherAttack(bleichenbacherTest);
                break;
            case InvalidCurveAttackCommandConfig.ATTACK_COMMAND:
                attacker = new InvalidCurveAttack(ellipticTest);
                break;
            case InvalidCurveAttackFullCommandConfig.ATTACK_COMMAND:
                attacker = new InvalidCurveAttackFull(elliptic);
                break;
            case HeartbleedCommandConfig.ATTACK_COMMAND:
                attacker = new HeartbleedAttack(heartbleed);
                break;
            case Lucky13CommandConfig.ATTACK_COMMAND:
                attacker = new Lucky13Attack(lucky13);
                break;
            case PoodleCommandConfig.ATTACK_COMMAND:
                attacker = new PoodleAttack(poodle);
                break;
            case PaddingOracleCommandConfig.ATTACK_COMMAND:
                attacker = new PaddingOracleAttack(paddingOracle);
                break;
            case Cve20162107CommandConfig.ATTACK_COMMAND:
                attacker = new Cve20162107(cve20162107);
                break;
            case WinshockCommandConfig.ATTACK_COMMAND:
                attacker = new WinshockAttack(winshock);
                break;
            case DtlsPaddingOracleAttackCommandConfig.ATTACK_COMMAND:
                attacker = new DtlsPaddingOracleAttack(dtlsPaddingOracleAttackTest);
                break;
            default:
                throw new ConfigurationException("No command found");
        }
        ConfigHandler configHandler = new ConfigHandler();
        if (configHandler.printHelpForCommand(jc, attacker.getConfig())) {
            return;
        }

        attacker.executeAttack(configHandler);

        TLSDelegateConfig config = attacker.getConfig();
        // TODO this is the attackers job, not ours
        // if (config.getWorkflowOutput() != null &&
        // !config.getWorkflowOutput().isEmpty()) {
        // logWorkflowTraces(attacker.getTlsContexts(),
        // config.getWorkflowOutput());
        // }
    }

    private static void startSimpleTlsClient(TLSDelegateConfig config) throws JAXBException, IOException {
        TlsConfig tlsConfig = config.createConfig();
        TlsClient client = new TlsClient();
        client.startTlsClient(tlsConfig);
    }

    private static void startSimpleTlsServer(TLSDelegateConfig config) throws JAXBException, IOException {
        TlsConfig tlsConfig = config.createConfig();
        TlsServer server = new TlsServer();
        server.startTlsServer(tlsConfig);
    }
}
