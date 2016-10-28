/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.calibration;

import tlsattacker.fuzzer.agents.Agent;
import tlsattacker.fuzzer.agents.AgentFactory;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.CalibrationConfig;
import tlsattacker.fuzzer.mutator.certificate.FixedCertificateMutator;
import tlsattacker.fuzzer.server.ServerManager;
import tlsattacker.fuzzer.server.TLSServer;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import tlsattacker.fuzzer.config.ConfigManager;

/**
 * A class that tries to find the lowest tls_timeout possible to such that
 * normal handshakes still execute probably with a tested Server.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TimeoutCalibrator {

    /**
     * We try to find the lowest Timeout that does not alter with Workflow
     * execution and
     * then multiply the number with the gain Factor
     */
    private double gainFactor = 0.2;

    /**
     * The highest timeout the calibrator consideres as useful
     */
    private int limit = 1000;

    /**
     * The configuration used for this command
     */
    private final CalibrationConfig config;

    public TimeoutCalibrator(CalibrationConfig config) {
	this.config = config;
	Security.addProvider(new BouncyCastleProvider());
    }

    public int getLimit() {
	return limit;
    }

    public void setLimit(int limit) {
	this.limit = limit;
    }

    public double getGainFactor() {
	return gainFactor;
    }

    public void setGainFactor(double gainFactor) {
	this.gainFactor = gainFactor;
    }

    /**
     * Calibrates the lowest timeout that all ciphersuites did support and multiplies it with the gain factor
     * @return Lowest timeout possible * gain factor
     */
    public int calibrateTimeout() {
	LOG.log(Level.INFO, "Calibrating Timeout, this may take some time.");
	return (int) (getLowestTimoutGlobal() * gainFactor);
    }

    /**
     * Calibrates the lowest timeout that all ciphersuite did support
     * @return Lowest timout supported
     */
    private int getLowestTimoutGlobal() {
	int highestTimeout = 0;
	FixedCertificateMutator mutator = new FixedCertificateMutator();

	for (ServerCertificateStructure serverCert : mutator.getServerPairList()) {
	    LOG.log(Level.INFO, "Grabbing supported Ciphersuites for {0}", serverCert.getCertificateFile()
		    .getAbsolutePath());
	    List<CipherSuite> supportedList = getWorkingCiphersuites(serverCert);
	    LOG.log(Level.INFO, "Finished grabbing");

	    for (CipherSuite suite : supportedList) {
		int localSmall = getSmallestTimeoutPossible(serverCert, suite);
		LOG.log(Level.INFO, "Lowest Timeout for {0} is {1}", new Object[] { suite.name(), localSmall });
		if (localSmall > highestTimeout) {
		    LOG.log(Level.INFO, "Found a new highest timeout!");
		    highestTimeout = localSmall;
		}
	    }
	}

	return highestTimeout;
    }

    /**
     * Tries to find all Ciphersuites that the server certificate supports
     * @param serverCerts The certificate to start the server with
     * @return List of all ciphersuites that the server certificate supports
     */
    private List<CipherSuite> getWorkingCiphersuites(ServerCertificateStructure serverCerts) {
	List<CipherSuite> workingCipherSuites = new LinkedList<>();
	List<CipherSuite> ciperSuiteList = CipherSuite.getImplemented();

	for (CipherSuite ciphersuite : ciperSuiteList) {
	    if (testCiphersuite(serverCerts, ciphersuite, limit)) {
		workingCipherSuites.add(ciphersuite);
	    }
	}
	return workingCipherSuites;
    }

    /**
     * Tests if a ciphersuite leads to a succesful handshake with the server with the specified timeout and certificate
     * 
     * @param serverCerts The certificate the server should be started with
     * @param suite The ciphersuite be tested
     * @param timeout The timeout that should be used
     * @return True if a successful handshake was executed with the server
     */
    public boolean testCiphersuite(ServerCertificateStructure serverCerts, CipherSuite suite, int timeout) {

	TLSServer server = ServerManager.getInstance().getFreeServer();
	boolean result = true;
	try {
	    Agent agent = AgentFactory.generateAgent(config, serverCerts);
	    agent.applicationStart(server);
	    try {
		Thread.sleep(200);
	    } catch (InterruptedException ex) {
		Logger.getLogger(TimeoutCalibrator.class.getName()).log(Level.SEVERE, null, ex);
	    }
	    GeneralConfig generalConfig = new GeneralConfig();
	    generalConfig.setLogLevel(org.apache.logging.log4j.Level.OFF);
	    ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	    configHandler.initialize(generalConfig);
	    ClientCommandConfig config = new ClientCommandConfig();
	    config.setConnect(server.getIp() + ":" + server.getPort());
	    config.setTlsTimeout(timeout);

	    List<CipherSuite> supportedCipers = new LinkedList<>();
	    supportedCipers.add(suite);
	    config.setCipherSuites(supportedCipers);
	    result &= executeWorkflow(configHandler, config, agent, server);
	    agent.applicationStop(server);
	} catch (Exception E) {
	    return false;
	} finally {
	    server.release();
	}
	return result;
    }

    /**
     * Executes a workflow specified in the client command config
     * @param configHandler Configuration handler used
     * @param config ClientCommandConfig which ultimately contains the TLSContext
     * @param agent The Agent that should be used
     * @param server The Server that should be used
     * @return True if the Workflowtrace did successfully execute
     */
    private boolean executeWorkflow(ConfigHandler configHandler, ClientCommandConfig config, Agent agent,
	    TLSServer server) {

	long time = System.currentTimeMillis();
	TransportHandler transportHandler = null;
	int counter = 0;
	while (transportHandler == null) {
	    try {
		transportHandler = configHandler.initializeTransportHandler(config);
	    } catch (ConfigurationException E) {
		// It may happen that the implementation is not ready
		// yet
		if (time + ConfigManager.getInstance().getConfig().getTimeout() < System.currentTimeMillis()) {
		    LOG.log(java.util.logging.Level.FINE, "Could not start Server! Trying to Restart it!");
		    agent.applicationStop(server);
		    agent.applicationStart(server);
		    time = System.currentTimeMillis();
		    counter++;
		}
		if (counter >= 5) {
		    throw new ConfigurationException("Could not start TLS Server, check your configuration Files!");
		}
	    }
	}
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	trace.makeGeneric();
	tlsContext.setWorkflowTrace(trace);
	try {

	    workflowExecutor.executeWorkflow();
	} catch (Exception E) {
	    return false;
	} finally {
	    transportHandler.closeConnection();
	}
	return isWorkflowTraceReasonable(tlsContext.getWorkflowTrace());
    }

    /**
     * Tests if all required messages were actually received in a WorkflowTrace
     * @param trace WorkflowTrace  to analyze
     * @return True if all required messages were actually received
     */
    private boolean isWorkflowTraceReasonable(WorkflowTrace trace) {
	int counter = 0;
	for (ProtocolMessage configuredMessage : trace.getAllConfiguredMessages()) {
	    if (counter >= trace.getAllExecutedMessages().size()) {
		return false;
	    }
	    ProtocolMessage receivedMessage = trace.getAllExecutedMessages().get(counter);
	    if (configuredMessage.getClass().equals(ArbitraryMessage.class)) {
		break;
	    }
	    if (configuredMessage.getClass() != receivedMessage.getClass()) {
		if (configuredMessage.isRequired()) {
		    return false;
		}
	    } else {
		counter++;
	    }
	}
	return (!trace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty());
    }

    /**
     * Tries to find the lowest timeout for a ciphersuite
     * @param serverCerts Certificate to start the Server with
     * @param suite Ciphersuite to test
     * @return Lowest timeout in milliseconds
     */
    private int getSmallestTimeoutPossible(ServerCertificateStructure serverCerts, CipherSuite suite) {
	int lowerEnd = 0;
	int higherEnd = limit;
	int testedTimeout = higherEnd / 2;
	do {
	    System.out.println("" + testedTimeout + " " + lowerEnd + " " + higherEnd);
	    boolean result = testCiphersuite(serverCerts, suite, testedTimeout);
	    if (result) {
		// The ciphersuite still executed fine, lower the testedTimeout
		higherEnd = testedTimeout;
	    } else {
		// the ciphersuite did not execute properly, raise the timeout
		lowerEnd = testedTimeout;
	    }
	    testedTimeout = lowerEnd + ((higherEnd - lowerEnd) / 2);
	    // we dont care about cornercases just return higher end and we good
	    if (higherEnd - lowerEnd <= 5) {
		return higherEnd;
	    }
	} while (testedTimeout != lowerEnd && testedTimeout != higherEnd);
	return testedTimeout;
    }
    
    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(TimeoutCalibrator.class
	    .getName());
}
