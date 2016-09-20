/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.executor;

import tlsattacker.fuzzer.agents.Agent;
import tlsattacker.fuzzer.agents.AgentFactory;
import tlsattacker.fuzzer.config.ConfigManager;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.logging.Logger;
import org.apache.logging.log4j.Level;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;
import tlsattacker.fuzzer.result.Result;
import tlsattacker.fuzzer.result.ResultContainer;
import tlsattacker.fuzzer.server.ServerManager;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class DebugExecutor {

    private static final Logger LOG = Logger.getLogger(DebugExecutor.class.getName());

    public static Result execute(TestVector vector, EvolutionaryFuzzerConfig config) {
	vector.getTrace().reset();
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");

	TransportHandler transportHandler = null;
	TLSServer server = null;
	try {
	    Agent agent = AgentFactory.generateAgent(config, vector.getServerKeyCert());
	    server = ServerManager.getInstance().getFreeServer();

	    agent.applicationStart(server);

	    GeneralConfig gc = new GeneralConfig();
	    gc.setLogLevel(Level.OFF);
	    configHandler.initialize(gc);

	    long time = System.currentTimeMillis();
	    int counter = 0;
	    while (transportHandler == null) {
		try {
		    while (transportHandler == null) {
			try {
			    transportHandler = initTransportHandler(server, config);
			} catch (ConfigurationException E) {
			    // It may happen that the implementation is not
			    // ready
			    // yet
			    if (time + ConfigManager.getInstance().getConfig().getTimeout() < System
				    .currentTimeMillis()) {
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

		} catch (ConfigurationException E) {
		    // It may happen that the implementation is not ready yet
		    if (time + ConfigManager.getInstance().getConfig().getTimeout() < System.currentTimeMillis()) {
			System.out.println("Could not start Server! Trying to Restart it!");
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

	    config.setKeystore(vector.getClientKeyCert().getJKSfile().getAbsolutePath());
	    config.setPassword(vector.getClientKeyCert().getPassword());
	    config.setAlias(vector.getClientKeyCert().getAlias());
	    KeyStore ks = KeystoreHandler.loadKeyStore(config.getKeystore(), config.getPassword());
	    TlsContext tlsContext = configHandler.initializeTlsContext(ConfigManager.getInstance().getConfig());
	    tlsContext.setFuzzingMode(true);
	    tlsContext.setKeyStore(ks);
	    tlsContext.setAlias(config.getAlias());
	    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
	    Collection<? extends Certificate> certs = (Collection<? extends Certificate>) certFactory
		    .generateCertificates(new FileInputStream(vector.getServerKeyCert().getCertificateFile()));

	    Certificate sunCert = (Certificate) certs.toArray()[0];
	    byte[] certBytes = sunCert.getEncoded();

	    ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
	    org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);

	    org.bouncycastle.asn1.x509.Certificate[] certs2 = new org.bouncycastle.asn1.x509.Certificate[1];
	    certs2[0] = cert;
	    org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs2);

	    X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));

	    tlsContext.setX509ServerCertificateObject(x509CertObject);
	    tlsContext.setServerCertificate(cert);
	    tlsContext.setFuzzingMode(true);
	    tlsContext.setWorkflowTrace(vector.getTrace());

	    WorkflowExecutor workflowExecutor = new GenericWorkflowExecutor(transportHandler, tlsContext,
		    vector.getExecutorType());

	    // tlsContext.setServerCertificate(certificate);
	    try {
		workflowExecutor.executeWorkflow();
	    } catch (WorkflowExecutionException ex) {
		ex.printStackTrace();
	    }
	    transportHandler.closeConnection();
	    // TODO What if server never exited?
	    agent.applicationStop(server);
	    File branchTrace = new File(ConfigManager.getInstance().getConfig().getTracesFolder().getAbsolutePath()
		    + "/" + server.getID());
	    try {
		Result r = agent.collectResults(branchTrace, vector);
		branchTrace.delete();
		return r;
	    } catch (Exception E) {
		E.printStackTrace();
	    }

	} catch (KeyStoreException | IOException ex) {
	    Logger.getLogger(DebugExecutor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
	} catch (CertificateParsingException ex) {
	    Logger.getLogger(DebugExecutor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
	} catch (CertificateEncodingException ex) {
	    Logger.getLogger(DebugExecutor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
	} catch (CertificateException ex) {
	    Logger.getLogger(DebugExecutor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
	} catch (Throwable t) {
	    t.printStackTrace();
	} finally {
	    server.release();
	}
	return null;
    }

    private static TransportHandler initTransportHandler(TLSServer server, EvolutionaryFuzzerConfig config) {
	TransportHandler th = TransportHandlerFactory.createTransportHandler(config.getTransportHandlerType(),
		config.getTlsTimeout());
	try {
	    th.initialize(server.getIp(), server.getPort());
	    th.setTimeout(config.getTlsTimeout());
	    return th;
	} catch (ArrayIndexOutOfBoundsException | NullPointerException | NumberFormatException ex) {
	    throw new ConfigurationException("Server not properly configured!");
	} catch (IOException ex) {
	    throw new ConfigurationException("Unable to initialize the transport handler with: " + server.getIp() + ":"
		    + server.getPort(), ex);
	}
    }
}
