/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignatureAndHashAlgorithmsExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignatureAndHashAlgorithmsExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignatureAndHashAlgorithmsExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SignatureAndHashAlgorithmsExtensionHandler extends
        ExtensionHandler<SignatureAndHashAlgorithmsExtensionMessage> {

    public SignatureAndHashAlgorithmsExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSContext(SignatureAndHashAlgorithmsExtensionMessage message) {
        List<SignatureAndHashAlgorithm> algoList = new LinkedList<>();
        byte[] signatureAndHashBytes = message.getSignatureAndHashAlgorithms().getValue();
        if (signatureAndHashBytes.length % HandshakeByteLength.SIGNATURE_HASH_ALGORITHM != 0) {
            throw new AdjustmentException(
                    "Cannot adjust ClientSupportedSignature and Hash algorithms to a resonable Value");
        }
        for (int i = 0; i < signatureAndHashBytes.length; i += HandshakeByteLength.SIGNATURE_HASH_ALGORITHM) {
            byte[] algoBytes = Arrays.copyOfRange(signatureAndHashBytes, i, i
                    + HandshakeByteLength.SIGNATURE_HASH_ALGORITHM);
            SignatureAndHashAlgorithm algo = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(algoBytes);
            if (algo == null || algo.getSignatureAlgorithm() == null || algo.getHashAlgorithm() == null) {
                LOGGER.warn("Unknown SignatureAndHashAlgorithm:" + ArrayConverter.bytesToHexString(algoBytes));
            } else {
                algoList.add(algo);
            }
        }
        context.setClientSupportedSignatureAndHashAlgorithms(algoList);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionParser getParser(byte[] message, int pointer) {
        return new SignatureAndHashAlgorithmsExtensionParser(pointer, message);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionPreparator getPreparator(
            SignatureAndHashAlgorithmsExtensionMessage message) {
        return new SignatureAndHashAlgorithmsExtensionPreparator(context.getChooser(), message);
    }

    @Override
    public SignatureAndHashAlgorithmsExtensionSerializer getSerializer(
            SignatureAndHashAlgorithmsExtensionMessage message) {
        return new SignatureAndHashAlgorithmsExtensionSerializer(message);
    }

}
