/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.fuzzer.impl;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttack;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttack;
import de.rub.nds.tlsattacker.fuzzer.config.SimpleFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.util.FuzzingHelper;
import static de.rub.nds.tlsattacker.fuzzer.util.FuzzingHelper.MAX_MODIFICATION_COUNT;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableAnalyzer;
import de.rub.nds.tlsattacker.modifiablevariable.util.ModifiableVariableField;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.TlsContextAnalyzer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ServerStartCommandExecutor;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class SimpleFuzzer extends Fuzzer {

    public static Logger LOGGER = LogManager.getLogger(SimpleFuzzer.class);

    private final SimpleFuzzerConfig fuzzerConfig;

    private String fuzzingName = "";

    private boolean interruptFuzzing;

    private Certificate certificate;

    private final List<WorkflowTrace> validWorkflowTraces;

    private ConfigHandler configHandler;

    private ServerStartCommandExecutor sce;

    private final Set<String> variablesWithoutHandshakeInfluence;

    private long totalProtocolFlows = 0;

    public SimpleFuzzer(SimpleFuzzerConfig fuzzerConfig, GeneralConfig generalConfig) {
	super(generalConfig);
	this.fuzzerConfig = fuzzerConfig;
	validWorkflowTraces = new LinkedList<>();
	variablesWithoutHandshakeInfluence = new HashSet<>();
    }

    @Override
    public void startFuzzer() {

	configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(generalConfig);

	String logFolder = initializeLogFolder();

	try {
	    if (fuzzerConfig.containsServerCommand()) {
		sce = startTestServer(fuzzerConfig.getResultingServerCommand());
	    }

	    try {
		gatherWorkflowsAndCertificate();
	    } catch (ConfigurationException ex) {
		LOGGER.error(ex.getLocalizedMessage());
	    }

	    startFuzzing(logFolder);

	} catch (ConfigurationException | JAXBException | IOException | IllegalAccessException
		| IllegalArgumentException ex) {
	    // throw new ConfigurationException(ex.getLocalizedMessage(), ex);
	    LOGGER.error(ex.getLocalizedMessage(), ex);
	} finally {
	    if (fuzzerConfig.containsServerCommand() && !sce.isServerTerminated()) {
		sce.terminateServer();
		// LOGGER.info(sce.getServerOutputString());
		// LOGGER.info(sce.getServerErrorOutputString());
	    }
	}
    }

    private void gatherWorkflowsAndCertificate() {
	LOGGER.info("Gathering workflows from {}", fuzzerConfig.getWorkflowFolder());
	File folder = new File(fuzzerConfig.getWorkflowFolder());
	File[] listOfFiles = folder.listFiles();

	List<File> xmlFiles = new LinkedList<>();
	for (File file : listOfFiles) {
	    if (file.isFile() && file.getName().endsWith(".xml")) {
		xmlFiles.add(file);
	    }
	}

	for (File file : xmlFiles) {
	    try {
		LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Executing the TLS workflow according to {}", file.getPath());
		fuzzerConfig.setWorkflowInput(file.getAbsolutePath());
		TransportHandler transportHandler = configHandler.initializeTransportHandler(fuzzerConfig);
		TlsContext tlsContext = configHandler.initializeTlsContext(fuzzerConfig);
		WorkflowTrace tmpTrace = (WorkflowTrace) UnoptimizedDeepCopy.copy(tlsContext.getWorkflowTrace());
		tmpTrace.setName(file.getName());
		WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler,
			tlsContext);
		workflowExecutor.executeWorkflow();
		transportHandler.closeConnection();
		if (TlsContextAnalyzer.containsFullWorkflow(tlsContext)) {
		    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Successfully executed {}", file.getPath());
		    if (certificate == null) {
			certificate = tlsContext.getServerCertificate();
		    }
		    validWorkflowTraces.add(tmpTrace);
		}
	    } catch (WorkflowExecutionException | ConfigurationException ex) {
		LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Not possible to execute a correct workflow",
			ex.getLocalizedMessage());
		LOGGER.debug(ex);
	    }
	}
    }

    private void startFuzzing(String logFolder) throws IOException, ConfigurationException, JAXBException,
	    IllegalAccessException, IllegalArgumentException {
	LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Starting fuzzing {}", fuzzingName);
	if (fuzzerConfig.isStage1()) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Starting stage 1: crypto fuzzing ");
	    startCryptoFuzzing();
	}
	if (fuzzerConfig.isStage2()) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Starting stage 2: tls fuzzing for boundary violations");
	    phase1(logFolder);
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "The following variables do not influence handshake (check manually for false-positives): {} ",
		    variablesWithoutHandshakeInfluence);
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Phase 1 is over, starting phase 2");
	    phase23(2, logFolder);
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Phase 2 is over, starting phase 3");
	    phase23(3, logFolder);
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Phase 3 finished");
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Total protocol flows: {}", totalProtocolFlows);
	}
    }

    private void startCryptoFuzzing() {
	Attacker attacker;

	BleichenbacherCommandConfig bb = new BleichenbacherCommandConfig();
	bb.setConnect(fuzzerConfig.getConnect());
	attacker = new BleichenbacherAttack(bb);
	attacker.executeAttack(configHandler);

	InvalidCurveAttackCommandConfig icea = new InvalidCurveAttackCommandConfig();
	icea.setConnect(fuzzerConfig.getConnect());
	attacker = new InvalidCurveAttack(icea);
	attacker.executeAttack(configHandler);

	PoodleCommandConfig poodle = new PoodleCommandConfig();
	poodle.setConnect(fuzzerConfig.getConnect());
	attacker = new PoodleAttack(poodle);
	attacker.executeAttack(configHandler);

	PaddingOracleCommandConfig po = new PaddingOracleCommandConfig();
	po.setConnect(fuzzerConfig.getConnect());
	attacker = new PaddingOracleAttack(po);
	attacker.executeAttack(configHandler);

    }

    /**
     * Use the TLS protocol flows and modify systematically specific variables.
     * The output of this phase is a list of variables that are most probably
     * not correctly checked by the server.
     * 
     * @param logFolder
     * @throws IOException
     * @throws JAXBException
     */
    private void phase1(String logFolder) throws IOException, JAXBException {
	for (WorkflowTrace trace : validWorkflowTraces) {
	    List<ModifiableVariableField> fields = FuzzingHelper.getAllModifiableVariableFieldsRecursively(trace,
		    ConnectionEnd.CLIENT);

	    for (int fieldNumber = 0; fieldNumber < fields.size(); fieldNumber++) {
		if (!FuzzingHelper.isModifiableVariableModificationAllowed(fields.get(fieldNumber).getField(),
			fuzzerConfig.getModifiableVariableTypes(), fuzzerConfig.getModifiableVariableFormats(),
			fuzzerConfig.getModifiedVariableWhitelist(), fuzzerConfig.getModifiedVariableBlacklist())) {
		    LOGGER.debug("skipping {}", fields.get(fieldNumber).getField().getName());
		    continue;
		}
		boolean influencesHandshake = false;
		String currentFieldName = "";
		String currentMessageName = "";
		for (int iter = 1; iter < fuzzerConfig.getVariableModificationIter() + 1; iter++) {
		    TlsContext tlsContext = createTlsContext(trace);
		    WorkflowTrace workflow = tlsContext.getWorkflowTrace();
		    List<ModifiableVariableField> currentFields = FuzzingHelper
			    .getAllModifiableVariableFieldsRecursively(workflow, ConnectionEnd.CLIENT);
		    ModifiableVariableField mvField = currentFields.get(fieldNumber);
		    currentFieldName = mvField.getField().getName();
		    currentMessageName = mvField.getObject().getClass().getSimpleName();
		    FuzzingHelper.executeModifiableVariableModification((ModifiableVariableHolder) mvField.getObject(),
			    mvField.getField());
		    TransportHandler transportHandler = configHandler.initializeTransportHandler(fuzzerConfig);
		    WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler,
			    tlsContext);
		    tlsContext.setServerCertificate(certificate);
		    try {
			workflowExecutor.executeWorkflow();
		    } catch (WorkflowExecutionException ex) {
			LOGGER.debug(ex.getLocalizedMessage(), ex);
		    }
		    transportHandler.closeConnection();
		    if (!TlsContextAnalyzer.containsFullWorkflow(tlsContext)) {
			if (workflow.containsServerFinished() || workflow.getProtocolMessages().size() == 2) {
			    influencesHandshake = true;
			}
		    }
		    // if the server was terminated, write file
		    analyzeServerTerminationAndWriteFile(sce, logFolder, currentFieldName, trace.getName(), iter,
			    workflow);
		    // if the workflow contains an unexpected fields /
		    // messages,
		    // write them to a file
		    analyzeResultingTlsContextAndWriteFile(tlsContext, logFolder, currentFieldName, trace.getName(),
			    iter);
		    totalProtocolFlows++;
		    if (interruptFuzzing) {
			return;
		    }
		}
		if (influencesHandshake) {
		    variablesWithoutHandshakeInfluence.add(currentMessageName + "." + currentFieldName);
		}

	    }
	}
    }

    private void phase23(int phase, String logFolder) throws IOException, JAXBException {
	long iter = 0;
	while (!interruptFuzzing && iter < fuzzerConfig.getRandomModificationIter()) {
	    try {
		iter++;
		if (iter % 1000 == 0) {
		    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Iteration {} in phase {}.", iter, phase);
		}
		WorkflowTrace validWorkflow = pickRandomTrace();
		TlsContext tlsContext = createTlsContext(validWorkflow);
		WorkflowTrace workflow = tlsContext.getWorkflowTrace();

		if (phase == 3) {
		    executeProtocolModificationPhase(workflow, tlsContext.getMyConnectionEnd());
		}
		addRandomRecords(workflow, ConnectionEnd.CLIENT);
		executeRandomFieldModifications(workflow, ConnectionEnd.CLIENT);
		TransportHandler transportHandler = configHandler.initializeTransportHandler(fuzzerConfig);
		WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler,
			tlsContext);
		tlsContext.setServerCertificate(certificate);
		try {
		    workflowExecutor.executeWorkflow();
		} catch (WorkflowExecutionException ex) {
		    LOGGER.debug(ex.getLocalizedMessage(), ex);
		}
		transportHandler.closeConnection();

		// if the server was terminated, write file
		analyzeServerTerminationAndWriteFile(sce, logFolder, "", validWorkflow.getName(), iter, workflow);
		if (interruptFuzzing) {
		    return;
		}
		// if the workflow contains an unexpected fields /
		// messages,
		// write them to a file
		analyzeResultingTlsContextAndWriteFile(tlsContext, logFolder, "", validWorkflow.getName(), iter);
		totalProtocolFlows++;
	    } catch (ConfigurationException | IOException | JAXBException ex) {
		LOGGER.debug(ex.getLocalizedMessage(), ex);
	    }
	}
    }

    private TlsContext createTlsContext(WorkflowTrace workflowTrace) {
	TlsContext tlsContext = new TlsContext();
	WorkflowTrace tmpTrace = (WorkflowTrace) UnoptimizedDeepCopy.copy(workflowTrace);
	tlsContext.setWorkflowTrace(tmpTrace);
	WorkflowConfigurationFactory.initializeProtocolMessageOrder(tlsContext);
	return tlsContext;
    }

    private WorkflowTrace createClientTrace(WorkflowTrace workflowTrace) {
	WorkflowTrace tmpTrace = (WorkflowTrace) UnoptimizedDeepCopy.copy(workflowTrace);
	for (int i = tmpTrace.getProtocolMessages().size() - 1; i >= 0; i--) {
	    if (tmpTrace.getProtocolMessages().get(i).getMessageIssuer() == ConnectionEnd.SERVER) {
		tmpTrace.getProtocolMessages().remove(i);
	    }
	}
	return tmpTrace;
    }

    private WorkflowTrace pickRandomTrace() {
	Random r = new Random();
	int pos = r.nextInt(validWorkflowTraces.size());
	return validWorkflowTraces.get(pos);
    }

    private ModifiableVariableField pickRandomField(List<ModifiableVariableField> fields) {
	Random r = new Random();
	while (true) {
	    int fieldNumber = r.nextInt(fields.size());
	    if (FuzzingHelper.isModifiableVariableModificationAllowed(fields.get(fieldNumber).getField(),
		    fuzzerConfig.getModifiableVariableTypes(), fuzzerConfig.getModifiableVariableFormats(),
		    fuzzerConfig.getModifiedVariableWhitelist(), fuzzerConfig.getModifiedVariableBlacklist())) {
		return fields.get(fieldNumber);
	    }
	}
    }

    private void startSystematicFuzzing(ConfigHandler configHandler, Certificate certificate,
	    ServerStartCommandExecutor sce, String folder) throws JAXBException, IOException, IllegalAccessException,
	    IllegalArgumentException {
	long phase = 0;
	interruptFuzzing = false;

	while (!interruptFuzzing) {
	    try {
		TlsContext tmpTlsContext = configHandler.initializeTlsContext(fuzzerConfig);
		WorkflowTrace tmpWorkflow = tmpTlsContext.getWorkflowTrace();

		// executeProtocolModification(tmpWorkflow,
		// tmpTlsContext.getMyConnectionEnd());
		addRandomRecords(tmpWorkflow, ConnectionEnd.CLIENT);

		List<ModifiableVariableField> fields = ModifiableVariableAnalyzer
			.getAllModifiableVariableFieldsRecursively(tmpWorkflow);
		for (int fieldNumber = 0; fieldNumber < fields.size(); fieldNumber++) {
		    if (!FuzzingHelper.isModifiableVariableModificationAllowed(fields.get(fieldNumber).getField(),
			    fuzzerConfig.getModifiableVariableTypes(), fuzzerConfig.getModifiableVariableFormats(),
			    fuzzerConfig.getModifiedVariableWhitelist(), fuzzerConfig.getModifiedVariableBlacklist())) {
			System.out.println("skipping " + fields.get(fieldNumber).getField().getName());
			continue;
		    }
		    for (int i = 0; i < fuzzerConfig.getGenerateMessagePercentage(); i++) {
			if (fuzzerConfig.containsServerCommand() && fuzzerConfig.isRestartServerInEachInteration()) {
			    sce = startTestServer(fuzzerConfig.getResultingServerCommand());
			}
			TlsContext tlsContext = configHandler.initializeTlsContext(fuzzerConfig);
			WorkflowTrace workflow = (WorkflowTrace) UnoptimizedDeepCopy.copy(tmpWorkflow);
			tlsContext.setWorkflowTrace(workflow);
			List<ModifiableVariableField> currentFields = ModifiableVariableAnalyzer
				.getAllModifiableVariableFieldsRecursively(workflow);
			ModifiableVariableField mvField = currentFields.get(fieldNumber);
			FuzzingHelper.executeModifiableVariableModification(
				(ModifiableVariableHolder) mvField.getObject(), mvField.getField());
			TransportHandler transportHandler = configHandler.initializeTransportHandler(fuzzerConfig);
			WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler,
				tlsContext);
			tlsContext.setServerCertificate(certificate);
			try {
			    workflowExecutor.executeWorkflow();
			} catch (WorkflowExecutionException ex) {
			    LOGGER.debug(ex.getLocalizedMessage(), ex);
			}
			transportHandler.closeConnection();
			phase++;
			// if the server was terminated, terminate fuzzing
			analyzeServerTerminationAndWriteFile(sce, folder, "", "", phase, workflow);
			// if the workflow contains an unexpected fields /
			// messages,
			// write them to a file
			String fieldName = fields.get(fieldNumber).getField().getName();
			analyzeResultingTlsContextAndWriteFile(tlsContext, folder, fieldName, "", phase);

			if (fuzzerConfig.isRestartServerInEachInteration()) {
			    sce.terminateServer();
			}
		    }
		}
	    } catch (ConfigurationException ex) {
		LOGGER.info(ex.getLocalizedMessage(), ex);
	    }
	}
    }

    private void executeRandomFieldModifications(WorkflowTrace workflow, ConnectionEnd peer) {
	while (FuzzingHelper.executeFuzzingUnit(fuzzerConfig.getModifyVariablePercentage())) {
	    FuzzingHelper.executeRandomModifiableVariableModification(workflow, peer,
		    fuzzerConfig.getModifiableVariableTypes(), fuzzerConfig.getModifiableVariableFormats(),
		    fuzzerConfig.getModifiedVariableWhitelist(), fuzzerConfig.getModifiedVariableBlacklist());
	}
    }

    private void executeProtocolModificationPhase(WorkflowTrace workflow, ConnectionEnd myConnectionEnd) {
	int i = 0;
	while (i < MAX_MODIFICATION_COUNT
		&& FuzzingHelper.executeFuzzingUnit(fuzzerConfig.getGenerateMessagePercentage())) {
	    i++;
	    FuzzingHelper.addRandomProtocolMessage(workflow, myConnectionEnd);
	}
	i = 0;
	while (i < MAX_MODIFICATION_COUNT
		&& FuzzingHelper.executeFuzzingUnit(fuzzerConfig.getNotSendingMessagePercantage())) {
	    i++;
	    FuzzingHelper.removeRandomProtocolMessage(workflow, myConnectionEnd);
	}
    }

    private void addRandomRecords(WorkflowTrace workflow, ConnectionEnd myConnectionEnd) {
	int i = 0;
	while (i < MAX_MODIFICATION_COUNT && FuzzingHelper.executeFuzzingUnit(fuzzerConfig.getAddRecordPercentage())) {
	    i++;
	    FuzzingHelper.addRecordsAtRandom(workflow, myConnectionEnd);
	}
    }

    /**
     * Analyzes whether the server was terminated. If yes, the fuzzing is
     * stopped
     * 
     * @param sce
     * @param folder
     * @param phase
     * @param workflow
     * @throws IOException
     * @throws JAXBException
     */
    private void analyzeServerTerminationAndWriteFile(ServerStartCommandExecutor sce, String folder,
	    String variableName, String workflowName, long phase, WorkflowTrace workflow) throws IOException,
	    JAXBException {
	if (fuzzerConfig.containsServerCommand() && sce.isServerTerminated()) {
	    interruptFuzzing = true;
	    FileOutputStream fos = new FileOutputStream(folder + "/terminated" + variableName + workflowName
		    + Long.toString(phase) + ".xml");
	    WorkflowTraceSerializer.write(fos, workflow);
	    LOGGER.error(sce.getServerErrorOutputString());
	    LOGGER.error(sce.getServerOutputString());
	}
    }

    /**
     * Analyzes the resulting workflow. It stores the workflow if the workflow
     * contains a missing message, or if it contains an unexpected new message,
     * or if it contains a modified message.
     * 
     * @param tlsContext
     * @param folder
     * @param phase
     * @param fieldName
     * @throws JAXBException
     * @throws IOException
     */
    private void analyzeResultingTlsContextAndWriteFile(TlsContext tlsContext, String folder, String fieldName,
	    String workflowName, long phase) throws JAXBException, IOException {
	if (TlsContextAnalyzer.containsFullWorkflowWithMissingMessage(tlsContext)
		|| TlsContextAnalyzer.containsServerFinishedWithModifiedHandshake(tlsContext)
		// ||
		// TlsContextAnalyzer.containsAlertAfterMissingMessage(tlsContext)
		// == TlsContextAnalyzer.AnalyzerResponse.NO_ALERT
		|| TlsContextAnalyzer.containsFullWorkflowWithModifiedMessage(tlsContext)) {
	    String fileNameBasic = createFileName(folder, phase, tlsContext, fieldName);
	    FileOutputStream fos = new FileOutputStream(fileNameBasic + workflowName + ".xml");
	    WorkflowTraceSerializer.write(fos, tlsContext.getWorkflowTrace());
	}
    }

    private ServerStartCommandExecutor startTestServer(String serverCommand) throws IOException {
	sce = new ServerStartCommandExecutor(serverCommand);
	sce.startServer();
	try {
	    Thread.sleep(2500);
	} catch (InterruptedException ex) {
	}
	return sce;
    }

    private String initializeLogFolder() throws ConfigurationException {
	DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss");
	Calendar cal = Calendar.getInstance();
	String folder = fuzzerConfig.getOutputFolder() + fuzzingName + dateFormat.format(cal.getTime());
	File f = new File(folder);
	boolean created = f.mkdir();
	if (!created) {
	    throw new ConfigurationException("Unable to create a log folder " + folder);
	}
	return folder;
    }

    private String createFileName(String folder, long phase, TlsContext tlsContext, String fieldName) {
	String fileNameBasic = folder + "/" + Long.toString(phase);
	if (TlsContextAnalyzer.containsFullWorkflowWithMissingMessage(tlsContext)) {
	    fileNameBasic += "-missing-";
	}
	if (TlsContextAnalyzer.containsServerFinishedWithModifiedHandshake(tlsContext)) {
	    fileNameBasic += "-modifiedhandshake-";
	}
	if (TlsContextAnalyzer.containsFullWorkflowWithModifiedMessage(tlsContext)) {
	    fileNameBasic += "-fullmod-";
	}
	fileNameBasic += fieldName;
	return fileNameBasic;
    }

    public void setFuzzingName(String fuzzingName) {
	this.fuzzingName = fuzzingName;
    }

}
