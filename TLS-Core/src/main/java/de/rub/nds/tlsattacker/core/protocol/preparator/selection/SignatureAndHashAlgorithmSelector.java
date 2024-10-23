/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.selection;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureAndHashAlgorithmSelector {

    public static SignatureAndHashAlgorithm selectSignatureAndHashAlgorithm(
            Chooser chooser, boolean restrictToTls13MessageSigningAlgorithms) {
        SignatureAndHashAlgorithm signHashAlgo;
        if (chooser.getConfig().getAutoAdjustSignatureAndHashAlgorithm()) {
            X509PublicKeyType publicKeyType;
            if (chooser.getTalkingConnectionEnd() == ConnectionEndType.SERVER) {
                publicKeyType =
                        chooser.getContext()
                                .getTlsContext()
                                .getServerX509Context()
                                .getChooser()
                                .getSubjectPublicKeyType();
            } else {
                publicKeyType =
                        chooser.getContext()
                                .getTlsContext()
                                .getClientX509Context()
                                .getChooser()
                                .getSubjectPublicKeyType();
            }
            List<SignatureAndHashAlgorithm> candidateList = new LinkedList<>();
            List<SignatureAndHashAlgorithm> peerSupported;
            List<SignatureAndHashAlgorithm> ourSupported;
            if (chooser.getTalkingConnectionEnd() == ConnectionEndType.SERVER) {
                peerSupported = chooser.getClientSupportedSignatureAndHashAlgorithms();
                ourSupported = chooser.getServerSupportedSignatureAndHashAlgorithms();
            } else {
                peerSupported = chooser.getServerSupportedSignatureAndHashAlgorithms();
                ourSupported = chooser.getClientSupportedSignatureAndHashAlgorithms();
            }
            for (SignatureAndHashAlgorithm tempSignatureAndHashAlgorithm : ourSupported) {
                if (publicKeyType.canBeUsedWithSignatureAlgorithm(
                        tempSignatureAndHashAlgorithm.getSignatureAlgorithm())) {
                    candidateList.add(tempSignatureAndHashAlgorithm);
                }
            }

            candidateList.retainAll(peerSupported);
            if (restrictToTls13MessageSigningAlgorithms) {
                // restrict to TLS 1.3 allowed algorithms
                candidateList =
                        candidateList.stream()
                                .filter(SignatureAndHashAlgorithm::suitedForSigningTls13Messages)
                                .collect(Collectors.toList());
            }
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
