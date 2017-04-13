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
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.config.Lucky13CommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.WinshockCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttacker;
import de.rub.nds.tlsattacker.attacks.impl.Cve20162107Attacker;
import de.rub.nds.tlsattacker.attacks.impl.DtlsPaddingOracleAttacker;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttacker;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttacker;
import de.rub.nds.tlsattacker.attacks.impl.Lucky13Attacker;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttacker;
import de.rub.nds.tlsattacker.attacks.impl.WinshockAttacker;
import de.rub.nds.tlsattacker.main.TLSClient;
import de.rub.nds.tlsattacker.testsuite.config.ServerTestSuiteConfig;
import de.rub.nds.tlsattacker.testsuite.impl.ServerTestSuite;
import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.impl.TestTLSServer;
import de.rub.nds.tlsattacker.attacks.impl.Attacker;
import de.rub.nds.tlsattacker.attacks.impl.EarlyCCSAttacker;
import de.rub.nds.tlsattacker.tls.client.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tlsserver.ServerCommandConfig;
import de.rub.nds.tlsattacker.tlsserver.TlsServer;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.TLSScanner;
import java.io.IOException;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger("Main");

    public static void main(String[] args) throws Exception {

        GeneralDelegate generalDelegate = new GeneralDelegate();
        JCommander jc = new JCommander(generalDelegate);
        BleichenbacherCommandConfig bleichenbacherTest = new BleichenbacherCommandConfig(generalDelegate);
        jc.addCommand(BleichenbacherCommandConfig.ATTACK_COMMAND, bleichenbacherTest);
        DtlsPaddingOracleAttackCommandConfig dtlsPaddingOracleAttackTest = new DtlsPaddingOracleAttackCommandConfig(
                generalDelegate);
        jc.addCommand(DtlsPaddingOracleAttackCommandConfig.ATTACK_COMMAND, dtlsPaddingOracleAttackTest);
        InvalidCurveAttackConfig ellipticTest = new InvalidCurveAttackConfig(generalDelegate);
        jc.addCommand(InvalidCurveAttackConfig.ATTACK_COMMAND, ellipticTest);
        HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig(generalDelegate);
        jc.addCommand(HeartbleedCommandConfig.ATTACK_COMMAND, heartbleed);
        Lucky13CommandConfig lucky13 = new Lucky13CommandConfig(generalDelegate);
        jc.addCommand(Lucky13CommandConfig.ATTACK_COMMAND, lucky13);
        PaddingOracleCommandConfig paddingOracle = new PaddingOracleCommandConfig(generalDelegate);
        jc.addCommand(PaddingOracleCommandConfig.ATTACK_COMMAND, paddingOracle);
        PoodleCommandConfig poodle = new PoodleCommandConfig(generalDelegate);
        jc.addCommand(PoodleCommandConfig.ATTACK_COMMAND, poodle);
        Cve20162107CommandConfig cve20162107 = new Cve20162107CommandConfig(generalDelegate);
        jc.addCommand(Cve20162107CommandConfig.ATTACK_COMMAND, cve20162107);
        WinshockCommandConfig winshock = new WinshockCommandConfig(generalDelegate);
        jc.addCommand(WinshockCommandConfig.ATTACK_COMMAND, winshock);
        EarlyCCSCommandConfig earlyCCS = new EarlyCCSCommandConfig(generalDelegate);
        jc.addCommand(EarlyCCSCommandConfig.ATTACK_COMMAND, earlyCCS);
        ServerCommandConfig server = new ServerCommandConfig(generalDelegate);
        jc.addCommand(ServerCommandConfig.COMMAND, server);
        ClientCommandConfig client = new ClientCommandConfig(generalDelegate);
        jc.addCommand(ClientCommandConfig.COMMAND, client);
        ServerTestSuiteConfig stconfig = new ServerTestSuiteConfig(generalDelegate);
        jc.addCommand(ServerTestSuiteConfig.COMMAND, stconfig);
        TestServerConfig testServerConfig = new TestServerConfig(generalDelegate);
        jc.addCommand(TestServerConfig.COMMAND, testServerConfig);
        ScannerConfig scannerConfig = new ScannerConfig(generalDelegate);
        jc.addCommand(ScannerConfig.COMMAND, scannerConfig);
        jc.parse(args);
        if (generalDelegate.isHelp() || jc.getParsedCommand() == null) {
            if (jc.getParsedCommand() == null) {
                jc.usage();
            } else {
                jc.usage(jc.getParsedCommand());
            }
            return;
        }
        Attacker<? extends TLSDelegateConfig> attacker = null;
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
            case ScannerConfig.COMMAND:
                TLSScanner scanner = new TLSScanner(scannerConfig);
                SiteReport report = scanner.scan();
                LOGGER.info("Scan Results:" + report.toString());
                return;
            case BleichenbacherCommandConfig.ATTACK_COMMAND:
                attacker = new BleichenbacherAttacker(bleichenbacherTest);
                break;
            case InvalidCurveAttackConfig.ATTACK_COMMAND:
                attacker = new InvalidCurveAttacker(ellipticTest);
                break;
            case HeartbleedCommandConfig.ATTACK_COMMAND:
                attacker = new HeartbleedAttacker(heartbleed);
                break;
            case Lucky13CommandConfig.ATTACK_COMMAND:
                attacker = new Lucky13Attacker(lucky13);
                break;
            case PoodleCommandConfig.ATTACK_COMMAND:
                attacker = new PoodleAttacker(poodle);
                break;
            case PaddingOracleCommandConfig.ATTACK_COMMAND:
                attacker = new PaddingOracleAttacker(paddingOracle);
                break;
            case Cve20162107CommandConfig.ATTACK_COMMAND:
                attacker = new Cve20162107Attacker(cve20162107);
                break;
            case WinshockCommandConfig.ATTACK_COMMAND:
                attacker = new WinshockAttacker(winshock);
                break;
            case DtlsPaddingOracleAttackCommandConfig.ATTACK_COMMAND:
                attacker = new DtlsPaddingOracleAttacker(dtlsPaddingOracleAttackTest);
                break;
            case EarlyCCSCommandConfig.ATTACK_COMMAND:
                attacker = new EarlyCCSAttacker(earlyCCS);
                break;
            default:
                throw new ConfigurationException("No command found");
        }
        if (attacker == null) {
            throw new ConfigurationException("Attacker not found");
        }
        if (isPrintHelpForCommand(jc, attacker.getConfig())) {
            jc.usage(jc.getParsedCommand());
        } else {

            if (attacker.getConfig().isExecuteAttack()) {
                attacker.executeAttack();
            } else {
                try {
                    Boolean result = attacker.isVulnerable();
                    LOGGER.info("Vulnerable:" + (result == null ? "Uncertain" : result.toString()));
                } catch (UnsupportedOperationException E) {
                    LOGGER.info("The selection is currently not implemented");
                }
            }
        }
    }

    private static void startSimpleTlsClient(TLSDelegateConfig config) throws JAXBException, IOException {
        TlsConfig tlsConfig = config.createConfig();
        TLSClient client = new TLSClient();
        client.startTlsClient(tlsConfig);
    }

    private static void startSimpleTlsServer(TLSDelegateConfig config) throws JAXBException, IOException {
        TlsConfig tlsConfig = config.createConfig();
        TlsServer server = new TlsServer();
        server.startTlsServer(tlsConfig);
    }

    public static boolean isPrintHelpForCommand(JCommander jc, TLSDelegateConfig config) {
        if (config.getGeneralDelegate().isHelp()) {
            return true;
        }
        return false;
    }
}
