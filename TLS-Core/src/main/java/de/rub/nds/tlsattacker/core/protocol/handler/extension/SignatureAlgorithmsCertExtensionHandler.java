/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAlgorithmsCertExtensionHandler
        extends ExtensionHandler<SignatureAlgorithmsCertExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureAlgorithmsCertExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(SignatureAlgorithmsCertExtensionMessage message) {
        byte[] algoBytes = message.getSignatureAndHashAlgorithms().getValue();
        List<SignatureAndHashAlgorithm> algoList =
                SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(algoBytes);
        tlsContext.setClientSupportedCertificateSignAlgorithms(algoList);
    }
}
