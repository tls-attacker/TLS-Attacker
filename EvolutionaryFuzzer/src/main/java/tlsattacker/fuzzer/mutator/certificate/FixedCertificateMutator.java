/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.mutator.certificate;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.eap.ClientHello;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import tlsattacker.fuzzer.analyzer.Rule;
import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.analyzer.RuleConfig;
import tlsattacker.fuzzer.config.ConfigManager;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.config.mutator.certificate.FixedCertificateMutatorConfig;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import tlsattacker.fuzzer.agents.AgentFactory;
import tlsattacker.fuzzer.agents.BlindAgent;
import tlsattacker.fuzzer.executor.TLSExecutor;
import tlsattacker.fuzzer.server.ServerManager;
import tlsattacker.fuzzer.server.TLSServer;
import tlsattacker.fuzzer.testvector.TestVector;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FixedCertificateMutator extends CertificateMutator {
    private FixedCertificateMutatorConfig config;
    private List<ClientCertificateStructure> clientCertList;
    private List<ServerCertificateStructure> serverPairList;
    private Random r;

    public FixedCertificateMutator() {
	EvolutionaryFuzzerConfig evoConfig = ConfigManager.getInstance().getConfig();
	String configFileName = "fixed_cert.config";
	File f = new File(evoConfig.getCertificateMutatorConfigFolder() + configFileName);
	if (f.exists()) {
	    config = JAXB.unmarshal(f, FixedCertificateMutatorConfig.class);
	} else {
	    LOG.log(Level.FINE, "No ConfigFile found:" + configFileName);
	}
	if (config == null) {
	    config = new FixedCertificateMutatorConfig();
	    serialize(f);
	}
	this.clientCertList = config.getClientCertificates();
	this.serverPairList = config.getServerCertificates();
	if (clientCertList.isEmpty() || serverPairList.isEmpty()) {
	    LOG.log(Level.INFO,
		    "The CertificateMutator is not properly configured. Make sure that the FixedCertificateMutator knows atleast one Client and one Server CertificatePair");
	    throw new ConfigurationException("CertificateMutator has not enough Certificates");
	}
	r = new Random();
	if (ConfigManager.getInstance().getConfig().isCertMutatorSelfTest()) {
	    selfTest();
	    ConfigManager.getInstance().getConfig().setCertMutatorSelftest(false);
	}
    }

    public void selfTest() {
	LOG.log(Level.INFO, "FixedCertificateMutator Configuration Self-test");
	testClientCerts();
        testServerCerts();
	
	LOG.log(Level.INFO, "Finished SelfTest");
    }
    private void testClientCerts()
    {
        LOG.log(Level.INFO, "Testing Client Certificates");
        for (ClientCertificateStructure clientCert : clientCertList) {
	    if (!clientCert.getJKSfile().exists()) {
		LOG.log(Level.INFO, "Could not find:" + clientCert.getJKSfile().getAbsolutePath());
	    }
            else
            {
              	LOG.log(Level.INFO, "" + clientCert.getJKSfile().getAbsolutePath() + " - OK");
	    }
	}
        LOG.log(Level.INFO, "Testing Client Certificates finished");
    }
    private void testServerCerts()
    {
        ConfigHandlerFactory.createConfigHandler("client").initialize(new GeneralConfig());
        
        LOG.log(Level.INFO, "Testing Server Certificates");
	for (ServerCertificateStructure serverStructure : serverPairList) {
	    if (!serverStructure.getCertificateFile().exists()) {
		LOG.log(Level.INFO, "Could not find:" + serverStructure.getCertificateFile().getAbsolutePath());
		continue;
	    }
	    if (!serverStructure.getKeyFile().exists()) {
		LOG.log(Level.INFO, "Could not find:" + serverStructure.getKeyFile().getAbsolutePath());
		continue;
	    }
	    TLSServer server = null;
	    try {
		server = ServerManager.getInstance().getFreeServer();
		try {
		    server.restart("", serverStructure.getCertificateFile(), serverStructure.getKeyFile());
		    if (!server.serverIsRunning()) {
			LOG.log(Level.INFO, "Could not start Server with:"
				+ serverStructure.getCertificateFile().getAbsolutePath());
                        continue;
		    }
		} catch (Exception E) {
		    LOG.log(Level.INFO, "Could not start Server with:"
			    + serverStructure.getCertificateFile().getAbsolutePath());
                    continue;
                }
	    } catch (Exception E) {
		LOG.log(Level.INFO, "Could not start Server with:"
			+ serverStructure.getCertificateFile().getAbsolutePath());
                continue;
            } finally {
		if (server != null) {
		    server.release();
		}
	    }
            CertificateFactory certFactory;
            try
            {
                certFactory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certs = (Collection<? extends Certificate>) certFactory
			.generateCertificates(new FileInputStream(serverStructure.getCertificateFile()));
                LOG.log(Level.INFO, serverStructure.getCertificateFile().getAbsolutePath() + " - OK");
            }
            catch (CertificateException | FileNotFoundException ex)
            {
                LOG.info("Certificate not supported by TLS-Attacker:"+serverStructure.getCertificateFile().getAbsolutePath());
                continue;
            }
		

	}
        LOG.log(Level.INFO, "Testing Server Certificates finished");
	    
    }

    public List<ClientCertificateStructure> getClientCertList() {
	return clientCertList;
    }

    public List<ServerCertificateStructure> getServerPairList() {
	return serverPairList;
    }

    @Override
    public ClientCertificateStructure getClientCertificateStructure() {
	return clientCertList.get(r.nextInt(clientCertList.size()));
    }

    @Override
    public ServerCertificateStructure getServerCertificateStructure() {
	return serverPairList.get(r.nextInt(serverPairList.size()));
    }

    public void serialize(File file) {
	if (!file.exists()) {
	    try {
		file.createNewFile();
	    } catch (IOException ex) {
		Logger.getLogger(FixedCertificateMutator.class.getName()).log(Level.SEVERE, null, ex);
	    }
	}
	JAXB.marshal(config, file);
    }

    private static final Logger LOG = Logger.getLogger(FixedCertificateMutator.class.getName());
}
