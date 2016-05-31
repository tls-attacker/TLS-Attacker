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
import java.io.FileFilter;
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

	List<String> successfulTests = new LinkedList<>();
	List<String> failedTests = new LinkedList<>();

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

	return (failedTests.isEmpty());
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
	    } catch (WorkflowExecutionException | ConfigurationException | IllegalArgumentException
		    | IllegalAccessException ex) {
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
