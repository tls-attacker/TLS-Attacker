/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.fuzzer.impl;

import de.rub.nds.tlsattacker.fuzzer.config.FuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.utils.CertificateHelper;
import de.rub.nds.tlsattacker.fuzzer.utils.FuzzingHelper;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ClientConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.TlsContextAnalyzer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ServerStartCommandExecutor;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Fuzzer extends Attacker<FuzzerConfig> {

    public static Logger LOGGER = LogManager.getLogger(Fuzzer.class);

    private boolean startingTlsServer;

    public Fuzzer(FuzzerConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {

	String serverCommand = null;
	if (config.getServerCommand() != null) {
	    serverCommand = config.getServerCommand();
	    startingTlsServer = true;
	} else if (config.getServerCommandFile() != null) {
	    serverCommand = config.getServerCommandFile();
	    startingTlsServer = true;
	}

	String folder = initializeLogFolder();

	try {
	    ServerStartCommandExecutor sce = null;
	    if (startingTlsServer) {
		sce = startTestServer(serverCommand);
	    }

	    Certificate certificate = CertificateHelper.fetchCertificate(config);
	    if (certificate == null) {
		LOGGER.error("No server certificate was fetched. Was the handshake executed correctly? Execute the program again.");
	    } else {
		startFuzzing(configHandler, certificate, sce, folder);
	    }

	    if (startingTlsServer && !sce.isServerTerminated()) {
		sce.terminateServer();
		LOGGER.info(sce.getServerOutputString());
		LOGGER.info(sce.getServerErrorOutputString());
	    }

	} catch (IOException | JAXBException ex) {
	    throw new ConfigurationException(ex.getLocalizedMessage(), ex);
	}
    }

    private void startFuzzing(ConfigHandler configHandler, Certificate certificate, ServerStartCommandExecutor sce,
	    String folder) throws ConfigurationException, JAXBException, IOException {
	long step = 0;
	while (true) {
	    TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	    TlsContext tlsContext = configHandler.initializeTlsContext(config);
	    WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	    WorkflowTrace workflow = tlsContext.getWorkflowTrace();
	    tlsContext.setServerCertificate(certificate);

	    while (FuzzingHelper.executeFuzzingUnit(config.getDuplicateMessagePercentage())) {
		FuzzingHelper.duplicateRandomProtocolMessage(workflow, tlsContext.getMyConnectionEnd());
	    }
	    while (FuzzingHelper.executeFuzzingUnit(config.getAddRecordPercentage())) {
		FuzzingHelper.addRecordsAtRandom(workflow, tlsContext.getMyConnectionEnd());
	    }
	    while (FuzzingHelper.executeFuzzingUnit(config.getModifyVariablePercentage())) {
		FuzzingHelper.executeRandomModifiableVariableModification(workflow, ConnectionEnd.CLIENT,
			config.getModifiableVariableTypes(), config.getModifiableVariableFormats(),
			config.getModifiedVariableWhitelist(), config.getModifiedVariableBlacklist());
	    }
	    while (FuzzingHelper.executeFuzzingUnit(config.getNotSendingMessagePercantage())) {
		FuzzingHelper.getRandomProtocolMessage(workflow, tlsContext.getMyConnectionEnd()).setGoingToBeSent(
			false);
	    }
	    try {
		workflowExecutor.executeWorkflow();
	    } catch (Exception ex) {
		LOGGER.debug(ex);
		ex.printStackTrace();
	    } finally {
		transportHandler.closeConnection();
		step++;
	    }
	    if (startingTlsServer && sce.isServerTerminated()) {
		FileOutputStream fos = new FileOutputStream(folder + "/" + Long.toString(step) + ".xml");
		WorkflowTraceSerializer.write(fos, workflow);
		return;
	    }
	    if (TlsContextAnalyzer.containsFullWorkflowWithMissingMessage(tlsContext)
		    || TlsContextAnalyzer.containsFullWorkflowWithUnexpectedMessage(tlsContext)
		    // ||
		    // TlsContextAnalyzer.containsAlertAfterMissingMessage(tlsContext)
		    // == TlsContextAnalyzer.AnalyzerResponse.NO_ALERT
		    || TlsContextAnalyzer.containsFullWorkflowWithModifiedMessage(tlsContext)) {
		String fileNameBasic = createFileName(folder, step, tlsContext);
		FileOutputStream fos = new FileOutputStream(fileNameBasic + ".xml");
		WorkflowTraceSerializer.write(fos, workflow);

		if (CertificateHelper.containsModifiedCertificate(tlsContext)) {
		    String fileName = fileNameBasic + "-cert.info";
		    CertificateHelper.writeModifiedCertInfoToFile(tlsContext, fileName);
		}

		if (config.isInterruptAfterFirstFinding()) {
		    return;
		}
	    }

	    // ByteArrayOutputStream bos = new ByteArrayOutputStream();
	    // WorkflowTraceSerializer.write(bos, workflow);
	    // System.out.println(new String(bos.toByteArray()));
	}
    }

    private String createFileName(String folder, long step, TlsContext tlsContext) {
	String fileNameBasic = folder + "/" + Long.toString(step);
	if (TlsContextAnalyzer.containsFullWorkflowWithMissingMessage(tlsContext)) {
	    fileNameBasic += "-missing";
	}
	if (TlsContextAnalyzer.containsFullWorkflowWithUnexpectedMessage(tlsContext)) {
	    fileNameBasic += "-unexpected";
	}
	if (TlsContextAnalyzer.containsFullWorkflowWithModifiedMessage(tlsContext)) {
	    fileNameBasic += "-fullmod";
	}
	return fileNameBasic;
    }

    private ServerStartCommandExecutor startTestServer(String serverCommand) throws IOException {
	ServerStartCommandExecutor sce = new ServerStartCommandExecutor(serverCommand);
	sce.startServer();
	try {
	    Thread.sleep(2000);
	} catch (InterruptedException ex) {
	}
	return sce;
    }

    private String initializeLogFolder() throws ConfigurationException {
	DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss");
	Calendar cal = Calendar.getInstance();
	String folder = "/tmp/" + dateFormat.format(cal.getTime());
	File f = new File(folder);
	boolean created = f.mkdir();
	if (!created) {
	    throw new ConfigurationException("Unable to create a log folder " + folder);
	}
	return folder;
    }
}
