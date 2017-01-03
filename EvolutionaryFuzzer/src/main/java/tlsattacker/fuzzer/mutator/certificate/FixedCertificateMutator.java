/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.mutator.certificate;

import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import javax.xml.bind.JAXB;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;
import tlsattacker.fuzzer.config.mutator.certificate.FixedCertificateMutatorConfig;
import tlsattacker.fuzzer.server.ServerManager;
import tlsattacker.fuzzer.server.TLSServer;

/**
 * An implementation of the CertificateMutator that does not modify the
 * Certificates and instead exchanges them completely.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class FixedCertificateMutator extends CertificateMutator {

    /**
     * The name of the CertificateMutator when referred by command line
     */
    public static final String optionName = "fixed";

    /**
     * The config to use
     */
    private FixedCertificateMutatorConfig config;

    /**
     * The list of clientCertificates that are used
     */
    private List<ClientCertificateStructure> clientCertList;

    /**
     * The list of serverCertificates that are used
     */
    private List<ServerCertificateStructure> serverCertList;

    /**
     * A Random object to help choose random ceriticates
     */
    private Random r;

    /**
     * EvolutionaryFuzzerConfig used
     */
    private final FuzzerGeneralConfig generalConfig;

    /**
     * The name of the config file //TODO should perhaps not be here
     */
    private final String configFileName = "fixed_cert.config";

    public FixedCertificateMutator(FuzzerGeneralConfig generalConfig) {
        this.generalConfig = generalConfig;
        File f = new File(generalConfig.getCertificateMutatorConfigFolder() + configFileName);
        if (f.exists()) {
            config = JAXB.unmarshal(f, FixedCertificateMutatorConfig.class);
        } else {
            LOGGER.debug("No ConfigFile found:" + configFileName);
        }
        if (config == null) {
            config = new FixedCertificateMutatorConfig(generalConfig);
            new File(generalConfig.getCertificateMutatorConfigFolder()).mkdirs();
            config.serialize(f);
        }
        this.clientCertList = config.getClientCertificates();
        this.serverCertList = config.getServerCertificates();
        if (clientCertList.isEmpty() || serverCertList.isEmpty()) {
            LOGGER.info("The CertificateMutator is not properly configured. Make sure that the "
                    + "FixedCertificateMutator knows atleast one Client and one Server CertificatePair");
            throw new ConfigurationException("CertificateMutator has not enough Certificates");
        }
        r = new Random();
    }

    /**
     * Tests all configured Certificates and if autofix is enabled stores the
     * fixed Config file.
     */
    public void selfTest() {
        LOGGER.info("FixedCertificateMutator Configuration Self-test");
        clientCertList = testClientCerts();
        serverCertList = testServerCerts();
        if (config.isAutofix()) {
            config.setClientCertificates(clientCertList);
            config.setServerCertificates(serverCertList);
            File f = new File(generalConfig.getCertificateMutatorConfigFolder() + configFileName);
            if (f.exists()) {
                f.delete();
            }
            config.serialize(f);
        }
        LOGGER.info("Finished SelfTest");
    }

    /**
     * Tests all ClientCertificates and returns a list of all working
     * ClientCertificates
     * 
     * @return A list of all working ClientCertificates
     */
    private List<ClientCertificateStructure> testClientCerts() {
        List<ClientCertificateStructure> workingCerts = new LinkedList<>();
        LOGGER.info("Testing Client Certificates");
        for (ClientCertificateStructure clientCert : clientCertList) {
            if (!clientCert.getJKSfile().exists()) {
                LOGGER.info("Could not find:{0}", clientCert.getJKSfile().getAbsolutePath());
            } else {
                LOGGER.info("{0} - OK", clientCert.getJKSfile().getAbsolutePath());
                workingCerts.add(clientCert);
            }
        }
        LOGGER.info("Testing Client Certificates finished");
        return workingCerts;
    }

    /**
     * Tests all ServerCertificates and returns a list of all working
     * ServerCertificates
     * 
     * @return A list of all working ServerCertificates
     */
    private List<ServerCertificateStructure> testServerCerts() {
        List<ServerCertificateStructure> workingCerts = new LinkedList<>();
        ConfigHandlerFactory.createConfigHandler("client").initialize(new GeneralConfig());

        LOGGER.info("Testing Server Certificates");
        for (ServerCertificateStructure serverStructure : serverCertList) {
            if (!serverStructure.getCertificateFile().exists()) {
                LOGGER.info("Could not find:{0}", serverStructure.getCertificateFile().getAbsolutePath());
                continue;
            }
            if (!serverStructure.getKeyFile().exists()) {
                LOGGER.info("Could not find:{0}", serverStructure.getKeyFile().getAbsolutePath());
                continue;
            }
            TLSServer server = null;
            try {
                server = ServerManager.getInstance().getFreeServer();
                try {
                    server.restart("", serverStructure.getCertificateFile(), serverStructure.getKeyFile());
                    if (!server.serverHasBooted()) {
                        LOGGER.info("Could not start Server with:{0}", serverStructure.getCertificateFile()
                                .getAbsolutePath());
                        continue;
                    }
                } catch (Exception E) {
                    LOGGER.info("Could not start Server with:{0}", serverStructure.getCertificateFile()
                            .getAbsolutePath());
                    continue;
                }
            } catch (Exception E) {
                LOGGER.info("Could not start Server with:{0}", serverStructure.getCertificateFile().getAbsolutePath());
                continue;
            } finally {
                if (server != null) {
                    server.release();
                }
            }
            CertificateFactory certFactory;
            try {
                // TODO Wrong certificate class
                certFactory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certs = certFactory.generateCertificates(new FileInputStream(
                        serverStructure.getCertificateFile()));
                workingCerts.add(serverStructure);
                LOGGER.info("{0} - OK", serverStructure.getCertificateFile().getAbsolutePath());
            } catch (Exception ex) {
                LOGGER.info("Certificate not supported by TLS-Attacker:{0}", serverStructure.getCertificateFile()
                        .getAbsolutePath());
                continue;
            }

        }
        LOGGER.info("Testing Server Certificates finished");
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

    /**
     * Checks if the ServerCertificate is in the serverCertList. This method
     * does not work as intended if the CertificateMutator is not properly
     * configured
     * 
     * @param structure
     *            Certificate to test
     * @return True if it is supported
     */
    @Override
    public boolean isSupported(ServerCertificateStructure structure) {
        return serverCertList.contains(structure);
    }

}
