/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testsuite.impl;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableAnalyzer;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.testsuite.config.ServerTestConfig;
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
import java.io.File;
import java.io.FilenameFilter;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerTestSuite extends TestSuite {

    public static Logger LOGGER = LogManager.getLogger(ServerTestSuite.class);

    private final ServerTestConfig testConfig;

    private ConfigHandler configHandler;

    public ServerTestSuite(ServerTestConfig serverTestConfig, GeneralConfig generalConfig) {
	super(generalConfig);
	this.testConfig = serverTestConfig;
    }

    @Override
    public boolean startTests() {
	configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);

	int successfulTests = 0;

	File folder = new File(testConfig.getFolder());
	File[] tests = folder.listFiles();
	for (File testFolder : tests) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Test Suite {} (one of these has to be succesful)",
		    testFolder.getName());
	    File[] testCases = testFolder.listFiles();
	    boolean successfulTest = false;
	    for (File testCase : testCases) {
		if (testCase.isDirectory()) {
		    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "  Running {}", testCase.getName());
		    if (startTestCase(testCase)) {
			// one of our test cases was successful
			successfulTest = true;
		    }
		}
	    }
	    if (successfulTest) {
		successfulTests++;
	    }
	}

	return (successfulTests > 0);
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
		    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "    {} passed", xmlFile.getName());
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
		    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "    {} failed", xmlFile.getName());
		    succesful = false;
		}
	    } catch (WorkflowExecutionException | ConfigurationException | IllegalArgumentException
		    | IllegalAccessException ex) {
		LOGGER.log(LogLevel.CONSOLE_OUTPUT, "    {} failed", xmlFile.getName());
		LOGGER.info(ex);
		succesful = false;
	    }
	}

	return succesful;
    }

}
