/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.handler.EmptyHandler;
import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.AlgorithmIdentifier;

public class OcspHashAlgorithmIdentifier extends AlgorithmIdentifier {

    public OcspHashAlgorithmIdentifier(String identifier) {
        super(identifier);
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return new EmptyHandler(chooser);
    }
}
