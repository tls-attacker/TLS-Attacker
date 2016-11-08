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
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

/**
 * A wrapper which logically binds a server private key file and a server
 * certificate file
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class ServerCertificateStructure implements Serializable {

    /**
     * The file which contains the private key
     */
    private File keyFile;

    /**
     * The file which contains the certificate
     */
    private File certificateFile;

    public ServerCertificateStructure(File keyFile, File certificateFile) {
	this.keyFile = keyFile;
	this.certificateFile = certificateFile;
    }

    private ServerCertificateStructure() {
        //JAXB magic
    }
    
    public File getKeyFile() {
	return keyFile;
    }

    public File getCertificateFile() {
	return certificateFile;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + Objects.hashCode(this.keyFile);
        hash = 97 * hash + Objects.hashCode(this.certificateFile);
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
	final ServerCertificateStructure other = (ServerCertificateStructure) obj;
	if (!Objects.equals(this.keyFile, other.keyFile)) {
	    return false;
	}
	return Objects.equals(this.certificateFile, other.certificateFile);
    }

    private static final Logger LOG = Logger.getLogger(ServerCertificateStructure.class.getName());

}
