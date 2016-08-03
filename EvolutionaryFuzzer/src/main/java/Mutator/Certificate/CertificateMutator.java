/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Mutator.Certificate;

import TestVector.ServerCertificateKeypair;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class CertificateMutator {
    public abstract X509CertificateObject getClientCertificate();

    public abstract ServerCertificateKeypair getServerCertificateKeypair();

}
