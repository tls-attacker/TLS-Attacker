/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateChainAnalyzer {

    private static final Logger LOGGER = LogManager.getLogger();

    public boolean isChainOrdered(X509CertificateChain chain, String uri) {
        return false; // TODO Implement
    }

    public boolean containsTrustAnchor(X509CertificateChain chain) {
        return false; // TODO Implement
    }

    public boolean containsKnownTrustAnchor(X509CertificateChain chain, List<TrustAnchor> anchor) {
        return false; // TODO Implement
    }

    public boolean containsMultipleLeafs(X509CertificateChain chain) {
        return false; // TODO Implement
    }

    public boolean containsValidLeaf(X509CertificateChain chain) {
        return false; // TODO Implement
    }

    public List<TrustPath> getAllTrustPaths(
            X509CertificateChain chain, List<TrustAnchor> trustAnchorList) {
        return new LinkedList<>();
    }

    public boolean containsExpiredCertificate(TrustPath path) {
        return false; // TODO Implement
    }

    public boolean containsExpiredCertificate(X509CertificateChain chain) {
        return false; // TODO Implement
    }

    public boolean containsNotYetValidCertificate(TrustPath path) {
        return false; // TODO Implement
    }

    public boolean containsNotYetValidCertificate(X509CertificateChain chain) {
        return false; // TODO Implement
    }

    public boolean containsWeakSignature(TrustPath path) {
        return false; // TODO Implement
    }

    public boolean containsSelfSignedLeaf(X509CertificateChain chain) {
        return false; // TODO Implement
    }

    public boolean hasIncompleteChain(X509CertificateChain chain) {
        return false; // TODO Implement
    }

    public boolean allSignaturesValid(X509CertificateChain chain) {
        return false; // TODO Implement
    }
}
