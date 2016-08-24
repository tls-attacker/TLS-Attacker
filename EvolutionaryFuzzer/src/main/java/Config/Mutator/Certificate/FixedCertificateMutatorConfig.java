/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config.Mutator.Certificate;

import Certificate.ClientCertificateStructure;
import Certificate.ServerCertificateStructure;
import Config.ConfigManager;
import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class FixedCertificateMutatorConfig implements Serializable {
    private ArrayList<ClientCertificateStructure> clientCertificates;
    private ArrayList<ServerCertificateStructure> serverCertificates;

    public FixedCertificateMutatorConfig() {
    }

    public FixedCertificateMutatorConfig(String test) {
	clientCertificates = new ArrayList<>();
	// Initialize the Config File with some certificates if we can find them
	new File(ConfigManager.getInstance().getConfig().getOutputClientCertificateFolder()).mkdirs();
	File jksFile = new File(ConfigManager.getInstance().getConfig().getOutputClientCertificateFolder()
		+ "ec256.jks");
	if (jksFile.exists()) {
	    clientCertificates.add(new ClientCertificateStructure("password", "alias", jksFile));
	}
	jksFile = new File(ConfigManager.getInstance().getConfig().getOutputClientCertificateFolder() + "rsa1024.jks");
	if (jksFile.exists()) {
	    clientCertificates.add(new ClientCertificateStructure("password", "alias", jksFile));
	}
	jksFile = new File(ConfigManager.getInstance().getConfig().getOutputClientCertificateFolder() + "rsa4096.jks");
	if (jksFile.exists()) {
	    clientCertificates.add(new ClientCertificateStructure("password", "alias", jksFile));
	}
	jksFile = new File(ConfigManager.getInstance().getConfig().getOutputClientCertificateFolder() + "rsa8192.jks");
	if (jksFile.exists()) {
	    clientCertificates.add(new ClientCertificateStructure("password", "alias", jksFile));
	}
	serverCertificates = new ArrayList<>();
	File keyFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "dsakey.pem");
	File certFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "dsacert.pem");
	if (keyFile.exists() && certFile.exists()) {
	    serverCertificates.add(new ServerCertificateStructure(keyFile, certFile));
	}
	keyFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder() + "ec256key.pem");
	certFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "ec256cert.pem");
	if (keyFile.exists() && certFile.exists()) {
	    serverCertificates.add(new ServerCertificateStructure(keyFile, certFile));
	}
	keyFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "rsa1024cert.pem");
	certFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "rsa1024key.pem");
	if (keyFile.exists() && certFile.exists()) {
	    // serverCertificates.add(new ServerCertificateStructure(keyFile,
	    // certFile)); //TODO
	}
	keyFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "rsa4096cert.pem");
	certFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "rsa4096key.pemm");
	if (keyFile.exists() && certFile.exists()) {
	    serverCertificates.add(new ServerCertificateStructure(keyFile, certFile));
	}
	keyFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "rsa8192cert.pem");
	certFile = new File(ConfigManager.getInstance().getConfig().getOutputServerCertificateFolder()
		+ "rsa8192key.pem");
	if (keyFile.exists() && certFile.exists()) {
	    // serverCertificates.add(new ServerCertificateStructure(keyFile,
	    // certFile));//TODO
	}
    }

    public ArrayList<ClientCertificateStructure> getClientCertificates() {
	return clientCertificates;
    }

    public void setClientCertificates(ArrayList<ClientCertificateStructure> clientCertificates) {
	this.clientCertificates = clientCertificates;
    }

    public ArrayList<ServerCertificateStructure> getServerCertificates() {
	return serverCertificates;
    }

    public void setServerCertificates(ArrayList<ServerCertificateStructure> serverCertificates) {
	this.serverCertificates = serverCertificates;
    }

}
