/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.AlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;

public class OcspHashAlgorithmIdentifier extends AlgorithmIdentifier {

    public OcspHashAlgorithmIdentifier(String identifier) {
        super(identifier);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getHandler'");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getParser'");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getPreparator'");
    }
}
