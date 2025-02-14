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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAndHashAlgorithmSelector {
    private static final Logger LOGGER = LogManager.getLogger();

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
            LOGGER.debug(
                    "Selecting SignatureAndHashAlgorithm for public key type {}", publicKeyType);
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
            // filter our supported algorithms to make a better fall-back decision if not match was
            // found
            ourSupported =
                    ourSupported.stream()
                            .filter(algo -> algo.suitableForSignatureKeyType(publicKeyType))
                            .collect(Collectors.toList());
            candidateList.addAll(ourSupported);
            candidateList.retainAll(peerSupported);
            if (restrictToTls13MessageSigningAlgorithms) {
                // restrict to TLS 1.3 allowed algorithms
                candidateList =
                        candidateList.stream()
                                .filter(SignatureAndHashAlgorithm::suitedForSigningTls13Messages)
                                .collect(Collectors.toList());
            }
            LOGGER.debug(
                    "Algorithm pairs supported by both peers, suitable for public key type, and protocol version: [{}]",
                    candidateList.stream()
                            .map(SignatureAndHashAlgorithm::name)
                            .collect(Collectors.joining(",")));
            if (candidateList.isEmpty()) {
                signHashAlgo = selectFallBackAlgorithm(chooser, ourSupported, publicKeyType);
                LOGGER.debug(
                        "No common algorithm found, selected fall-back algorithm {}", signHashAlgo);
            } else {
                signHashAlgo = candidateList.get(0);
            }
        } else {
            signHashAlgo = chooser.getConfig().getDefaultSelectedSignatureAndHashAlgorithm();
            LOGGER.debug("Using pre-configured algorithm pair {}", signHashAlgo);
        }
        return signHashAlgo;
    }

    /**
     * Selects a fall-back algorithm if no common algorithm was found. We always attempt to use an
     * algorithm suitable for the public key type first.
     *
     * @param chooser
     * @param ourSuitableSupported List of our configured SignatureAndHashAlgorithms matching the
     *     public key type
     * @param publicKeyType The public key type of the selected certificate
     * @return
     */
    private static SignatureAndHashAlgorithm selectFallBackAlgorithm(
            Chooser chooser,
            List<SignatureAndHashAlgorithm> ourSuitableSupported,
            X509PublicKeyType publicKeyType) {
        if (chooser.getSelectedSigHashAlgorithm().suitableForSignatureKeyType(publicKeyType)) {
            return chooser.getSelectedSigHashAlgorithm();
        } else if (!ourSuitableSupported.isEmpty()) {
            return ourSuitableSupported.get(0);
        }

        return chooser.getSelectedSigHashAlgorithm();
    }
}
