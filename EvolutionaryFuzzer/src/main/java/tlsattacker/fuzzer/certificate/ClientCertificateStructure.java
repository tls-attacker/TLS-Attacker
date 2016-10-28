/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.certificate;

import java.io.File;
import java.io.Serializable;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * A wrapper class which logically binds the JKSFile with the assosiated
 * password and alias.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientCertificateStructure implements Serializable {

    /**
     * Password for the JKS file
     */
    private String password;

    /**
     * Alias of the Certificate in the JKS File
     */
    private String alias;

    /**
     * The JKS file
     */
    private File JKSfile;

    public ClientCertificateStructure(String password, String alias, File JKSfile) {
	this.password = password;
	this.alias = alias;
	this.JKSfile = JKSfile;
    }

    public ClientCertificateStructure() {
	password = null;
	alias = null;
	JKSfile = null;
    }

    public String getPassword() {
	return password;
    }

    public void setPassword(String password) {
	this.password = password;
    }

    public String getAlias() {
	return alias;
    }

    public void setAlias(String alias) {
	this.alias = alias;
    }

    public File getJKSfile() {
	return JKSfile;
    }

    public void setJKSfile(File JKSfile) {
	this.JKSfile = JKSfile;
    }

    @Override
    public int hashCode() {
	int hash = 7;
	hash = 61 * hash + Objects.hashCode(this.password);
	hash = 61 * hash + Objects.hashCode(this.alias);
	hash = 61 * hash + Objects.hashCode(this.JKSfile);
	return hash;
    }

    @Override
    public boolean equals(Object obj) {
	if (obj == null) {
	    return false;
	}
	if (getClass() != obj.getClass()) {
	    return false;
	}
	final ClientCertificateStructure other = (ClientCertificateStructure) obj;
	if (!Objects.equals(this.password, other.password)) {
	    return false;
	}
	if (!Objects.equals(this.alias, other.alias)) {
	    return false;
	}
	return Objects.equals(this.JKSfile, other.JKSfile);
    }

    private static final Logger LOG = Logger.getLogger(ClientCertificateStructure.class.getName());

}
