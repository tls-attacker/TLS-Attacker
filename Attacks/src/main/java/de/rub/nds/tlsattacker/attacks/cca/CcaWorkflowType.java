/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca;

public enum CcaWorkflowType {
    CRT_CKE_CCS_FIN("TLS handshake flow with CertificateVerify omitted."),
    CRT_CKE_FIN("TLS handshake flow with CertificateVerify and CCS omitted."),
    CRT_CKE_ZFIN("TLS handshake flow with CertificateVerify and CCS omitted. Additionally the verify_data "
            + "in the FinishedMessage is set zeroes only."),
    CKE_CCS_FIN("TLS handshake completely ignoring the CertificateRequest. First seen in GnuTLS 3.3.9."),
    CKE_CCS_CRT_FIN_CCS_RND("Handshake abusing incorrect transitions in the JSEE state machine.");

    String description;

    CcaWorkflowType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
