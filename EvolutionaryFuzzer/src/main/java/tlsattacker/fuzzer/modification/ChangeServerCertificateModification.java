/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import java.util.logging.Logger;
import tlsattacker.fuzzer.certificate.ServerCertificateStructure;

/**
 * A modification which indicates that the server certificate in the TestVector
 * has changed.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeServerCertificateModification extends Modification {

    /**
     * Server certificate to which was changed
     */
    private final ServerCertificateStructure keyCertPair;

    public ChangeServerCertificateModification(ServerCertificateStructure keyCertPair) {
        super(ModificationType.CHANGE_SERVER_CERT);
        this.keyCertPair = keyCertPair;
    }

    public ServerCertificateStructure getKeyCertPair() {
        return keyCertPair;
    }

    private static final Logger LOG = Logger.getLogger(ChangeServerCertificateModification.class.getName());

}
