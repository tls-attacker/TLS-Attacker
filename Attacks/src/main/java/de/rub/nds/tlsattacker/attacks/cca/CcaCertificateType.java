/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca;

public enum CcaCertificateType {
    CLIENT_INPUT("The certificate provided to the CLI switch"),
    EMPTY("An empty certificate."),
    ROOTv3_CAv3_LEAF_RSAv3(
            "RSA Leaf certificate generated based on the provided (root-)CA certificate with one intermediate CA."),
    ROOTv1_CAv3_LEAFv1_nLEAF_RSAv3(
            "RSA Leaf Certificate generated with an intermediate Certificate that is v1 (actually not a CA).");
    // There will be several more cases later through this work, especially one
    // we start integrating X509 attacker.
    // This is just to start out modular enabling a combination of our test
    // vectors at a later date
    String description;

    CcaCertificateType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
