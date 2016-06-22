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
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackFullCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.ManInTheMiddleAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.WinshockCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttack;
import de.rub.nds.tlsattacker.attacks.impl.Cve20162107;
import de.rub.nds.tlsattacker.attacks.impl.DtlsPaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttackFull;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttack;
import de.rub.nds.tlsattacker.attacks.impl.ManInTheMiddleAttack;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttack;
import de.rub.nds.tlsattacker.attacks.impl.WinshockAttack;
import de.rub.nds.tlsattacker.fuzzer.config.MultiFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.impl.MultiFuzzer;
import de.rub.nds.tlsattacker.testsuite.config.ServerTestConfig;
import de.rub.nds.tlsattacker.testsuite.impl.ServerTestSuite;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.ServerCommandConfig;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
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

        GeneralConfig generalConfig = new GeneralConfig();
        JCommander jc = new JCommander(generalConfig);

        MultiFuzzerConfig cmconfig = new MultiFuzzerConfig();
        jc.addCommand(MultiFuzzerConfig.COMMAND, cmconfig);

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
        ManInTheMiddleAttackCommandConfig MitM_Attack = new ManInTheMiddleAttackCommandConfig();
        jc.addCommand(ManInTheMiddleAttackCommandConfig.ATTACK_COMMAND, MitM_Attack);
        ServerTestConfig stconfig = new ServerTestConfig();
        jc.addCommand(ServerTestConfig.COMMAND, stconfig);

        jc.parse(args);

        if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }

        Attacker attacker;
        switch (jc.getParsedCommand()) {
            case MultiFuzzerConfig.COMMAND:
                startMultiFuzzer(cmconfig, generalConfig, jc);
                return;
            case ServerCommandConfig.COMMAND:
                startSimpleTls(generalConfig, server, jc);
                return;
            case ClientCommandConfig.COMMAND:
                startSimpleTls(generalConfig, client, jc);
                return;
            case ServerTestConfig.COMMAND:
                ServerTestSuite st = new ServerTestSuite(stconfig, generalConfig);
                st.startTests();
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
            case ManInTheMiddleAttackCommandConfig.ATTACK_COMMAND:
                attacker = new ManInTheMiddleAttack(MitM_Attack);
                break;
            default:
                throw new ConfigurationException("No command found");
        }
        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
        configHandler.initialize(generalConfig);

        if (configHandler.printHelpForCommand(jc, attacker.getConfig())) {
            return;
        }

        attacker.executeAttack(configHandler);

        CommandConfig config = attacker.getConfig();
        if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
            logWorkflowTraces(attacker.getTlsContexts(), config.getWorkflowOutput());
        }
    }

    private static void startMultiFuzzer(MultiFuzzerConfig fuzzerConfig, GeneralConfig generalConfig, JCommander jc) {
        MultiFuzzer fuzzer = new MultiFuzzer(fuzzerConfig, generalConfig);
        if (fuzzerConfig.isHelp()) {
            jc.usage(MultiFuzzerConfig.COMMAND);
            return;
        }
        fuzzer.startFuzzer();
    }

    private static void startSimpleTls(GeneralConfig generalConfig, CommandConfig config, JCommander jc)
            throws JAXBException, IOException {
        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler(jc.getParsedCommand());
        configHandler.initialize(generalConfig);

        if (configHandler.printHelpForCommand(jc, config)) {
            return;
        }

        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
        TlsContext tlsContext = configHandler.initializeTlsContext(config);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info(ex.getLocalizedMessage(), ex);
            LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                    "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
        }

        transportHandler.closeConnection();

        if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
            FileOutputStream fos = new FileOutputStream(config.getWorkflowOutput());
            WorkflowTraceSerializer.write(fos, tlsContext.getWorkflowTrace());
        }
    }

    private static void logWorkflowTraces(List<TlsContext> tlsContexts, String fileName) throws JAXBException,
            FileNotFoundException, IOException {
        int i = 0;
        for (TlsContext context : tlsContexts) {
            i++;
            FileOutputStream fos = new FileOutputStream(fileName + i);
            WorkflowTraceSerializer.write(fos, context.getWorkflowTrace());
        }
    }
}
