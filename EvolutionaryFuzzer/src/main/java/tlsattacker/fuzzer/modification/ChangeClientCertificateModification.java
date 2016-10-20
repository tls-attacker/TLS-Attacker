/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.modification;

import tlsattacker.fuzzer.certificate.ClientCertificateStructure;

/**
 * A modification which indicates that the client certificate in the TestVector was changed
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeClientCertificateModification extends Modification {

    /**
     *
     */
    private final ClientCertificateStructure keyCertPair;

    /**
     *
     * @param keyCertPair
     */
    public ChangeClientCertificateModification(ClientCertificateStructure keyCertPair) {
	super(ModificationType.CHANGE_CLIENT_CERT);
	this.keyCertPair = keyCertPair;
    }

    /**
     *
     * @return
     */
    public ClientCertificateStructure getKeyCertPair() {
	return keyCertPair;
    }

}
