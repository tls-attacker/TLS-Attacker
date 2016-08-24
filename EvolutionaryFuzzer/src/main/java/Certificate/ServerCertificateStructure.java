/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Certificate;

import java.io.File;
import java.io.Serializable;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerCertificateStructure implements Serializable {// TODO
    private File keyFile;
    private File certificateFile;

    public ServerCertificateStructure(File keyFile, File certificateFile) {
	this.keyFile = keyFile;
	this.certificateFile = certificateFile;
    }

    public ServerCertificateStructure() {
	this.keyFile = null;
	this.certificateFile = null;
    }

    public File getKeyFile() {
	return keyFile;
    }

    public void setKeyFile(File keyFile) {
	this.keyFile = keyFile;
    }

    public File getCertificateFile() {
	return certificateFile;
    }

    public void setCertificateFile(File certificateFile) {
	this.certificateFile = certificateFile;
    }

}
