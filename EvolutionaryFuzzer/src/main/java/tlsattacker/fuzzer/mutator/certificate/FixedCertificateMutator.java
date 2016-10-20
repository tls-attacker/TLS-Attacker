/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.mutator.certificate;

import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.ConfigManager;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import tlsattacker.fuzzer.config.mutator.certificate.FixedCertificateMutatorConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import tlsattacker.fuzzer.server.ServerManager;
import tlsattacker.fuzzer.server.TLSServer;

/**
 * An implementation of the CertificateMutator that does not modify the Certificates and instead exchanges them completely.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FixedCertificateMutator extends CertificateMutator {
    public static final String optionName = "fixed";
    private static final Logger LOG = Logger.getLogger(FixedCertificateMutator.class.getName());
    private FixedCertificateMutatorConfig config;
    private List<ClientCertificateStructure> clientCertList;
    private List<ServerCertificateStructure> serverCertList;
    private Random r;
    private final String configFileName = "fixed_cert.config";

    
    public FixedCertificateMutator() {
	EvolutionaryFuzzerConfig evoConfig = ConfigManager.getInstance().getConfig();
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
	this.serverCertList = config.getServerCertificates();
	if (clientCertList.isEmpty() || serverCertList.isEmpty()) {
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
	clientCertList = testClientCerts();
	serverCertList = testServerCerts();
	if (config.isAutofix()) {
	    config.setClientCertificates(clientCertList);
	    config.setServerCertificates(serverCertList);
	    File f = new File(ConfigManager.getInstance().getConfig().getCertificateMutatorConfigFolder()
		    + configFileName);
	    if (f.exists()) {
		f.delete();
	    }
	    serialize(f);
	}

	LOG.log(Level.INFO, "Finished SelfTest");
    }

    private List<ClientCertificateStructure> testClientCerts() {
	List<ClientCertificateStructure> workingCerts = new LinkedList<>();
	LOG.log(Level.INFO, "Testing Client Certificates");
	for (ClientCertificateStructure clientCert : clientCertList) {
	    if (!clientCert.getJKSfile().exists()) {
		LOG.log(Level.INFO, "Could not find:" + clientCert.getJKSfile().getAbsolutePath());
	    } else {
		LOG.log(Level.INFO, "" + clientCert.getJKSfile().getAbsolutePath() + " - OK");
		workingCerts.add(clientCert);
	    }
	}
	LOG.log(Level.INFO, "Testing Client Certificates finished");
	return workingCerts;
    }

    private List<ServerCertificateStructure> testServerCerts() {
	List<ServerCertificateStructure> workingCerts = new LinkedList<>();
	ConfigHandlerFactory.createConfigHandler("client").initialize(new GeneralConfig());

	LOG.log(Level.INFO, "Testing Server Certificates");
	for (ServerCertificateStructure serverStructure : serverCertList) {
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
	    try {
		certFactory = CertificateFactory.getInstance("X.509");
		Collection<? extends Certificate> certs = certFactory
                        .generateCertificates(new FileInputStream(serverStructure.getCertificateFile()));
		workingCerts.add(serverStructure);
		LOG.log(Level.INFO, serverStructure.getCertificateFile().getAbsolutePath() + " - OK");
	    } catch (Exception ex) {
		LOG.info("Certificate not supported by TLS-Attacker:"
			+ serverStructure.getCertificateFile().getAbsolutePath());
		continue;
	    }

	}
	LOG.log(Level.INFO, "Testing Server Certificates finished");
	return workingCerts;
    }

    public List<ClientCertificateStructure> getClientCertList() {
	return Collections.unmodifiableList(clientCertList);
    }

    public List<ServerCertificateStructure> getServerPairList() {
	return Collections.unmodifiableList(serverCertList);
    }

    @Override
    public ClientCertificateStructure getClientCertificateStructure() {
	return clientCertList.get(r.nextInt(clientCertList.size()));
    }

    @Override
    public ServerCertificateStructure getServerCertificateStructure() {
	return serverCertList.get(r.nextInt(serverCertList.size()));
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

    @Override
    public boolean isSupported(ServerCertificateStructure structure) {
	if (serverCertList.contains(structure)) {
	    return true;
	} else {
	    return false;
	}
    }

}
