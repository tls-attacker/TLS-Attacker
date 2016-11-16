/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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

    /**
     * Returns a newly generated client certificate
     * 
     * @return Newly generated client certificate
     */
    public abstract ClientCertificateStructure getClientCertificateStructure();

    /**
     * Returns a newly generated server ceriticate
     * 
     * @return Newly generated server certificate
     */
    public abstract ServerCertificateStructure getServerCertificateStructure();

    /**
     * Checks if the ServerCertificate is supported by the implementation
     * 
     * @param structure
     *            ServerCertificate to check
     * @return True if the ServerCertificate is supported
     */
    public abstract boolean isSupported(ServerCertificateStructure structure);
}
