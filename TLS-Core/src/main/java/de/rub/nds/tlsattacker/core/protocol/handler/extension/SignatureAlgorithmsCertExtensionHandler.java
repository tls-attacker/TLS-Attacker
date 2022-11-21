/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignatureAlgorithmsCertExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignatureAlgorithmsCertExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignatureAlgorithmsCertExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

public class SignatureAlgorithmsCertExtensionHandler extends ExtensionHandler<SignatureAlgorithmsCertExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureAlgorithmsCertExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(SignatureAlgorithmsCertExtensionMessage message) {
        byte[] algoBytes = message.getSignatureAndHashAlgorithms().getValue();
        List<SignatureAndHashAlgorithm> algoList = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(algoBytes);
        context.setClientSupportedCertificateSignAlgorithms(algoList);
    }

    @Override
    public SignatureAlgorithmsCertExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new SignatureAlgorithmsCertExtensionParser(pointer, message, config);
    }

    @Override
    public SignatureAlgorithmsCertExtensionPreparator getPreparator(SignatureAlgorithmsCertExtensionMessage message) {
        return new SignatureAlgorithmsCertExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public SignatureAlgorithmsCertExtensionSerializer getSerializer(SignatureAlgorithmsCertExtensionMessage message) {
        return new SignatureAlgorithmsCertExtensionSerializer(message);
    }
}
