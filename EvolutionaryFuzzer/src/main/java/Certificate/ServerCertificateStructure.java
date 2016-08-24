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
    private String keyFilePath;
    private String certificateFilePath;

    public ServerCertificateStructure(File keyFile, File certificateFile) {
	this.keyFile = keyFile;
	this.certificateFile = certificateFile;
	this.keyFilePath = keyFile.getAbsolutePath();
	this.certificateFilePath = certificateFile.getAbsolutePath();
    }

    public ServerCertificateStructure() {
	this.keyFile = null;
	this.certificateFile = null;
	this.keyFilePath = null;
	this.certificateFilePath = null;

    }

    public File getKeyFile() {
	return keyFile;
    }

    public File getCertificateFile() {
	if (certificateFile == null && certificateFilePath != null) {
	    certificateFile = new File(certificateFilePath);
	}
	return certificateFile;
    }

    public String getKeyFilePath() {
	if (keyFile == null && keyFilePath != null) {
	    keyFile = new File(keyFilePath);
	}
	return keyFilePath;
    }

    public void setKeyFilePath(String keyFilePath) {
	this.keyFilePath = keyFilePath;
	keyFile = new File(keyFilePath);
    }

    public String getCertificateFilePath() {
	return certificateFilePath;
    }

    public void setCertificateFilePath(String certificateFilePath) {
	this.certificateFilePath = certificateFilePath;
	certificateFile = new File(certificateFilePath);
    }

}
