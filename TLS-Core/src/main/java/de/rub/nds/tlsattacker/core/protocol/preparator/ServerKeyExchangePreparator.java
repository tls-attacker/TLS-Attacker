/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.TlsSignatureUtil;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import java.util.LinkedList;
import java.util.List;

/**
 * @param <T> The ServerKeyExchangeMessage that should be prepared
 */
public abstract class ServerKeyExchangePreparator<T extends ServerKeyExchangeMessage>
        extends HandshakeMessagePreparator<T> {

    public ServerKeyExchangePreparator(Chooser chooser, T message) {
        super(chooser, message);
    }

    protected byte[] generateSignature(
            SignatureAndHashAlgorithm algorithm, byte[] toBeHashedAndSigned) {
        TlsSignatureUtil util = new TlsSignatureUtil();
        util.computeSignature(
                chooser,
                algorithm,
                toBeHashedAndSigned,
                message.getSignatureComputations(algorithm.getSignatureAlgorithm()));
        return message.getSignatureComputations(algorithm.getSignatureAlgorithm())
                .getSignatureBytes()
                .getValue();
    }

    protected SignatureAndHashAlgorithm chooseSignatureAndHashAlgorithm() {
        SignatureAndHashAlgorithm signHashAlgo;
        if (chooser.getConfig().getAutoAdjustSignatureAndHashAlgorithm()) {
            X509PublicKeyType publicKeyType =
                    chooser.getContext()
                            .getTlsContext()
                            .getServerX509Context()
                            .getChooser()
                            .getSubjectPublicKeyType();
            List<SignatureAndHashAlgorithm> candidateList = new LinkedList<>();
            for (SignatureAndHashAlgorithm tempSignatureAndHashAlgorithm :
                    SignatureAndHashAlgorithm.getImplemented()) {
                if (publicKeyType.canBeUsedWithSignatureAlgorithm(
                        tempSignatureAndHashAlgorithm.getSignatureAlgorithm())) {
                    candidateList.add(tempSignatureAndHashAlgorithm);
                }
            }

            List<SignatureAndHashAlgorithm> clientSupportedList =
                    chooser.getClientSupportedSignatureAndHashAlgorithms();

            candidateList.retainAll(clientSupportedList);
            if (candidateList.isEmpty()) {
                signHashAlgo = chooser.getSelectedSigHashAlgorithm();
            } else {
                signHashAlgo = candidateList.get(0);
            }
        } else {
            signHashAlgo = chooser.getConfig().getDefaultSelectedSignatureAndHashAlgorithm();
        }
        return signHashAlgo;
    }
}
