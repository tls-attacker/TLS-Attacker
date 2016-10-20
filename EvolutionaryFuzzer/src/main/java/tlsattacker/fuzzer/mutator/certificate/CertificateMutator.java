/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.mutator.certificate;

import tlsattacker.fuzzer.certificate.ClientCertificateStructure;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;

/**
 * A mutator super class that modifies Certificates.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class CertificateMutator {
    public abstract ClientCertificateStructure getClientCertificateStructure();

    public abstract ServerCertificateStructure getServerCertificateStructure();

    public abstract boolean isSupported(ServerCertificateStructure structure);

    public void serialize(File file) {
	if (!file.exists()) {
	    try {
		file.createNewFile();
	    } catch (IOException ex) {
		Logger.getLogger(FixedCertificateMutator.class.getName()).log(Level.SEVERE, null, ex);
	    }
	}
	JAXB.marshal(this, file);
    }
}
