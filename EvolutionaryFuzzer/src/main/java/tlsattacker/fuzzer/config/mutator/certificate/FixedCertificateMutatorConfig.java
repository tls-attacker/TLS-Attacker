/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config.mutator.certificate;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.bind.JAXB;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import tlsattacker.fuzzer.config.FuzzerGeneralConfig;

/**
 * A configuration class for the FixedCertificateMutator
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class FixedCertificateMutatorConfig implements Serializable {
    // Fixes the configuration File after a selftest and serializes it

    private static final Logger LOGGER = LogManager.getLogger(FixedCertificateMutatorConfig.class);

    /**
     * If set, the Configuration file deletes all incompatible or not found
     * certificates after calibration
     */
    private boolean autofix = true;

    /**
     * The list of client certificates
     */
    private List<ClientCertificateStructure> clientCertificates;

    /**
     * The list of server certificates
     */
    private List<ServerCertificateStructure> serverCertificates;

    /**
     * Config object used
     */
    @XmlTransient
    private FuzzerGeneralConfig config;

    public FixedCertificateMutatorConfig(FuzzerGeneralConfig config) {
        this.config = config;
        clientCertificates = new ArrayList<>();
        // Initialize the Config File with some certificates if we can find them
        new File("config/certificates/client/").mkdirs();
        File jksFile = new File("config/certificates/client/rsa1024.jks");
        if (jksFile.exists()) {
            clientCertificates.add(new ClientCertificateStructure("password", "alias", jksFile));
        }
        serverCertificates = new ArrayList<>();
        File keyFile = new File("config/certificates/server/dsakey.pem");
        File certFile = new File("config/certificates/server/dsacert.pem");
        if (keyFile.exists() && certFile.exists()) {
            serverCertificates.add(new ServerCertificateStructure(keyFile, certFile));
        }
    }

    private FixedCertificateMutatorConfig() {
        // Private Constructor for JAXB magic
    }

    /**
     * Serializes this config to a File
     * 
     * @param file
     *            File to serialize to
     */
    public void serialize(File file) {
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException ex) {
                LOGGER.error(ex.getLocalizedMessage(), ex);
            }
        }
        JAXB.marshal(this, file);
    }

    public boolean isAutofix() {
        return autofix;
    }

    public void setAutofix(boolean autofix) {
        this.autofix = autofix;
    }

    public List<ClientCertificateStructure> getClientCertificates() {
        return Collections.unmodifiableList(clientCertificates);
    }

    public void setClientCertificates(List<ClientCertificateStructure> clientCertificates) {
        this.clientCertificates = clientCertificates;
    }

    public List<ServerCertificateStructure> getServerCertificates() {
        return Collections.unmodifiableList(serverCertificates);
    }

    public void setServerCertificates(List<ServerCertificateStructure> serverCertificates) {
        this.serverCertificates = serverCertificates;
    }

}
