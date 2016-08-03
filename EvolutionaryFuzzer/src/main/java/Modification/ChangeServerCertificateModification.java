/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Modification;

import TestVector.ServerCertificateKeypair;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeServerCertificateModification extends Modification {
    private final ServerCertificateKeypair keyCertPair;

    public ChangeServerCertificateModification(ServerCertificateKeypair keyCertPair) {
	super(ModificationType.CHANGE_SERVER_CERT);
	this.keyCertPair = keyCertPair;
    }

    public ServerCertificateKeypair getKeyCertPair() {
	return keyCertPair;
    }

}
