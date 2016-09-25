/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testsuite.impl;

import java.io.File;
import java.io.FileFilter;
import java.io.FilenameFilter;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttack;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttack;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttack;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableAnalyzer;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.testsuite.config.ServerTestSuiteConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.TlsContextAnalyzer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerTestSuite extends TestSuite {

    public static Logger LOGGER = LogManager.getLogger(ServerTestSuite.class);

    private final ServerTestSuiteConfig testConfig;

    private ConfigHandler configHandler;

    public ServerTestSuite(ServerTestSuiteConfig serverTestConfig, GeneralConfig generalConfig) {
        super(generalConfig);
        this.testConfig = serverTestConfig;
    }

    @Override
    public boolean startTests() {
        configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);
        
        this.startAttackTests();
        this.startTestFromFiles();
        return failedTests.isEmpty();
    }

    private void startAttackTests() {
        Attacker<? extends CommandConfig> attacker;
        BleichenbacherCommandConfig bb = new BleichenbacherCommandConfig();
	bb.setConnect(testConfig.getConnect());
	attacker = new BleichenbacherAttack(bb);
	attacker.executeAttack(configHandler);
        if(attacker.isVulnerable()) {
            failedTests.add(BleichenbacherCommandConfig.ATTACK_COMMAND);
        } else {
            successfulTests.add(BleichenbacherCommandConfig.ATTACK_COMMAND);
        }

	InvalidCurveAttackCommandConfig icea = new InvalidCurveAttackCommandConfig();
	icea.setConnect(testConfig.getConnect());
	attacker = new InvalidCurveAttack(icea);
	attacker.executeAttack(configHandler);
        if(attacker.isVulnerable()) {
            failedTests.add(InvalidCurveAttackCommandConfig.ATTACK_COMMAND);
        } else {
            successfulTests.add(InvalidCurveAttackCommandConfig.ATTACK_COMMAND);
        }
        
        HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig();
        heartbleed.setConnect(testConfig.getConnect());
        attacker = new HeartbleedAttack(heartbleed);
        attacker.executeAttack(configHandler);
        if(attacker.isVulnerable()) {
            failedTests.add(HeartbleedCommandConfig.ATTACK_COMMAND);
        } else {
            successfulTests.add(HeartbleedCommandConfig.ATTACK_COMMAND);
        }

	PoodleCommandConfig poodle = new PoodleCommandConfig();
	poodle.setConnect(testConfig.getConnect());
	attacker = new PoodleAttack(poodle);
	attacker.executeAttack(configHandler);
        if(attacker.isVulnerable()) {
            failedTests.add(PoodleCommandConfig.ATTACK_COMMAND);
        } else {
            successfulTests.add(PoodleCommandConfig.ATTACK_COMMAND);
        }

	PaddingOracleCommandConfig po = new PaddingOracleCommandConfig();
	po.setConnect(testConfig.getConnect());
	attacker = new PaddingOracleAttack(po);
	attacker.executeAttack(configHandler);
        if(attacker.isVulnerable()) {
            failedTests.add(PaddingOracleCommandConfig.ATTACK_COMMAND);
        } else {
            successfulTests.add(PaddingOracleCommandConfig.ATTACK_COMMAND);
        }
        
        
    }

    private void startTestFromFiles() {
        File folder = new File(testConfig.getFolder());
        File[] testsuites = folder.listFiles(new DirectoryFilter());
        for (File testsuite : testsuites) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Starting {} Test Suite", testsuite.getName());
            File[] tests = testsuite.listFiles(new DirectoryFilter());
            for (File test : tests) {
                LOGGER.info("Testing {} (one of these has to be succesful)", test.getName());
                File[] testCases = test.listFiles(new DirectoryFilter());
                boolean successfulTest = false;
                for (File testCase : testCases) {
                    LOGGER.info("  Running {}", testCase.getName());
                    if (startTestCase(testCase)) {
                        // one of our test cases was successful
                        successfulTest = true;
                    }
                }
                if (successfulTest) {
                    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{} SUCCESSFUL ", test.getName());
                    successfulTests.add(test.getName());
                } else {
                    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{} FAILED ", test.getName());
                    failedTests.add(test.getName());
                }
            }
        }
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Summary of successful tests");
        for (String s : successfulTests) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "  {}", s);
        }
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Summary of failed tests");
        for (String s : failedTests) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "  {}", s);
        }
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Successful tests: {}", successfulTests.size());
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Failed tests: {}", failedTests.size());
    }

    private boolean startTestCase(File testFolder) {
        boolean succesful = true;

        File[] xmlFiles = testFolder.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.toLowerCase().endsWith(".xml");
            }
        });

        for (File xmlFile : xmlFiles) {
            try {
                testConfig.setWorkflowInput(xmlFile.getAbsolutePath());
                TransportHandler transportHandler = configHandler.initializeTransportHandler(testConfig);
                TlsContext tlsContext = configHandler.initializeTlsContext(testConfig);
                WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler,
                        tlsContext);
                workflowExecutor.executeWorkflow();
                transportHandler.closeConnection();
                if (TlsContextAnalyzer.containsFullWorkflow(tlsContext)) {
                    LOGGER.info("    {} passed", xmlFile.getName());
                    List<ModifiableVariableField> mvfs = ModifiableVariableAnalyzer
                            .getAllModifiableVariableFieldsRecursively(tlsContext.getWorkflowTrace());
                    for (ModifiableVariableField mvf : mvfs) {
                        ModifiableVariable mv = mvf.getModifiableVariable();
                        if (mv != null && mv.containsAssertion()) {
                            if (mv.validateAssertions()) {
                                LOGGER.info("    Assertion in {}.{} succesfully validated", mvf.getObject().getClass()
                                        .getSimpleName(), mvf.getField().getName());
                            } else {
                                LOGGER.info("    Assertion in {}.{} invalid", mvf.getObject().getClass()
                                        .getSimpleName(), mvf.getField().getName());
                                succesful = false;
                            }
                        }
                    }
                } else {
                    LOGGER.info("    {} failed", xmlFile.getName());
                    succesful = false;
                }
            } catch (WorkflowExecutionException | ConfigurationException | IllegalArgumentException | IllegalAccessException ex) {
                LOGGER.info("    {} failed", xmlFile.getName());
                LOGGER.info(ex);
                succesful = false;
            }
        }

        return succesful;
    }

    class DirectoryFilter implements FileFilter {

        @Override
        public boolean accept(File f) {
            return f.isDirectory();
        }

    };

}
