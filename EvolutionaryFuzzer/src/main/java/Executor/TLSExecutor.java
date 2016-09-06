/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Executor;

import Agents.Agent;
import Config.ConfigManager;
import Config.EvolutionaryFuzzerConfig;
import Exceptions.TimeoutException;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import de.rub.nds.tlsattacker.util.UnoptimizedDeepCopy;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.Level;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;
import Helper.LogFileIDManager;
import Result.Result;
import Result.ResultContainer;
import Server.TLSServer;
import TestVector.TestVector;
import TestVector.TestVectorSerializer;
import de.rub.nds.tlsattacker.dtls.workflow.Dtls12WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

/**
 * This is an Implementation of an Executor. This Executor is specially designed
 * for the TLS Protocol. The whole Program is not completely generic in this
 * Fashion designed, but with a little work the Fuzzer can be adapted for other
 * Programs, as long as a new Executor is designed.
 * 
 * It is also possible to Design a new Executor which executes the
 * Workflowtraces with another Library than TLS-Attacker.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class TLSExecutor extends Executor {

    private static final Logger LOG = Logger.getLogger(TLSExecutor.class.getName());

    private final TestVector testVector;
    private final TLSServer server;
    private final Agent agent;

    /**
     * Constructor for the TLSExecutor
     * 
     * @param trace
     *            Trace that the Executor should execute
     * @param server
     *            Server on which the Executor should execute the Trace
     */
    public TLSExecutor(TestVector testVector, TLSServer server, Agent agent) {
	this.testVector = testVector;
	this.server = server;
	this.agent = agent;

    }

    /**
     * Executes the Trace
     */
    @Override
    public void run() {

	try {
	    boolean timeout = false;
	    ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	    TransportHandler transportHandler = null;

	    try {
		// Load clientCertificate
		EvolutionaryFuzzerConfig fc = ConfigManager.getInstance().getConfig();
		// TODO This can be a problem when running with mutliple threads
		fc.setKeystore(testVector.getClientKeyCert().getJKSfile().getAbsolutePath());
		fc.setPassword(testVector.getClientKeyCert().getPassword());
		fc.setAlias(testVector.getClientKeyCert().getAlias());
		agent.applicationStart(server);
		GeneralConfig gc = new GeneralConfig();
		gc.setLogLevel(Level.OFF);
		configHandler.initialize(gc);

		long time = System.currentTimeMillis();
		int counter = 0;
		while (transportHandler == null) {
		    try {

			transportHandler = configHandler.initializeTransportHandler(fc);

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
			    throw new ConfigurationException(
				    "Could not start TLS Server, check your configuration Files!");
			}
		    }
		}
                transportHandler.setTimeout(ConfigManager.getInstance().getConfig().getTlsTimeout());
		KeyStore ks = KeystoreHandler.loadKeyStore(fc.getKeystore(), fc.getPassword());
		TlsContext tlsContext = configHandler.initializeTlsContext(ConfigManager.getInstance().getConfig());
		tlsContext.setFuzzingMode(true);
		tlsContext.setKeyStore(ks);
		tlsContext.setAlias(fc.getAlias());
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		Collection<? extends Certificate> certs = (Collection<? extends Certificate>) certFactory
			.generateCertificates(new FileInputStream(testVector.getServerKeyCert().getCertificateFile()));

		Certificate sunCert = (Certificate) certs.toArray()[0];
		byte[] certBytes = sunCert.getEncoded();

		ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
		org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
			.getInstance(asn1Cert);

		org.bouncycastle.asn1.x509.Certificate[] certs2 = new org.bouncycastle.asn1.x509.Certificate[1];
		certs2[0] = cert;
		org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs2);

		X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));

		tlsContext.setX509ServerCertificateObject(x509CertObject);
		tlsContext.setServerCertificate(cert);
		tlsContext.setWorkflowTrace(testVector.getTrace());
		WorkflowExecutor workflowExecutor = null;
		if (testVector.getExecutorType() == ExecutorType.TLS) {
		    workflowExecutor = new GenericWorkflowExecutor(transportHandler, tlsContext,
			    testVector.getExecutorType());
		} else {
		    workflowExecutor = new Dtls12WorkflowExecutor(transportHandler, tlsContext);

		}
		// tlsContext.setServerCertificate(certificate);
		workflowExecutor.executeWorkflow();
	    } catch (UnsupportedOperationException E) {
		// Skip Workflows we dont support yet
	    } catch (TimeoutException E) {
		timeout = true;
	    } catch (Throwable E) {
		File f = new File(ConfigManager.getInstance().getConfig().getOutputFaultyFolder()
			+ LogFileIDManager.getInstance().getFilename());

		try {
		    TestVectorSerializer.write(f, testVector);
		} catch (JAXBException | IOException Ex) {
		    LOG.log(java.util.logging.Level.INFO, "Could not serialize WorkflowTrace:{0}", f.getAbsolutePath());
		    Ex.printStackTrace();
		}
		LOG.log(java.util.logging.Level.INFO, "File:{0}", f.getName());
		E.printStackTrace();
	    } finally {
		if (transportHandler != null) {
		    transportHandler.closeConnection();
		}
		
		agent.applicationStop(server);
		File branchTrace = new File(ConfigManager.getInstance().getConfig().getTracesFolder().getAbsolutePath()
			+ "/" + server.getID());
		Result r = agent.collectResults(branchTrace, testVector);
		r.setDidTimeout(timeout);
		branchTrace.delete();
		ResultContainer.getInstance().commit(r);
		int id = server.getID();

		// Cleanup
		File file = new File(ConfigManager.getInstance().getConfig().getTracesFolder().getAbsolutePath() + "/"
			+ id);
		if (file.exists()) {
		    file.delete();
		}
	    }
	} finally {
	    server.release();
	}

    }

}
