/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignatureAndHashAlgorithmsExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignatureAndHashAlgorithmsExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignatureAndHashAlgorithmsExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import java.io.ByteArrayInputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAndHashAlgorithmsExtensionHandler
    extends ExtensionHandler<SignatureAndHashAlgorithmsExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureAndHashAlgorithmsExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(SignatureAndHashAlgorithmsExtensionMessage message) {
        byte[] algoBytes = message.getSignatureAndHashAlgorithms().getValue();
        List<SignatureAndHashAlgorithm> algoList = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(algoBytes);
        context.setClientSupportedSignatureAndHashAlgorithms(algoList);
        LOGGER.debug("Client supported signatureAndHashAlgorithms: " + algoList);
        adjustSelectedSignatureAndHashAlgorithm();
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new SignatureAndHashAlgorithmsExtensionParser(pointer, message, config);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionPreparator
        getPreparator(SignatureAndHashAlgorithmsExtensionMessage message) {
        return new SignatureAndHashAlgorithmsExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionSerializer
        getSerializer(SignatureAndHashAlgorithmsExtensionMessage message) {
        return new SignatureAndHashAlgorithmsExtensionSerializer(message);
    }

    private void adjustSelectedSignatureAndHashAlgorithm() {
        for (SignatureAndHashAlgorithm algo : context.getChooser().getClientSupportedSignatureAndHashAlgorithms()) {
            if (context.getChooser().getServerSupportedSignatureAndHashAlgorithms().contains(algo)) {
                context.setSelectedSignatureAndHashAlgorithm(algo);
                LOGGER.debug("Adjusting selected signature and hash algorithm to: " + algo.name());
                return;
            }
        }
        LOGGER.warn("Client and Server have no signature and hash algorithm in common");
    }
}
