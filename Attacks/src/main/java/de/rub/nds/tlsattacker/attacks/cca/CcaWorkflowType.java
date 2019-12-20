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
            + "in the FinishedMessage is set zeroes only. Supposely found in CyaSSL 3.2.0"),
    CKE_CCS_FIN("TLS handshake completely ignoring the CertificateRequest. First seen in GnuTLS 3.3.9."),
    CKE_CCS_CRT_FIN_CCS_RND("Handshake abusing incorrect transitions in the JSEE state machine."),
    CRT_CCS_FIN("TLS handshake omitting the ClientKeyExchange and CertificateVerify. This might lead to null "
            + "keys or non deterministic keys being established. Additionally same state machines might be confused "
            + "leading to a ClientAuthentication bypass."),
    CRT_FIN("TLS handshake of only ClientCertificate and Finished. No encryption is enabled and no "
            + "key material is sent from the client. Uninitialized data might be used, or null keys."),
    CRT_ZFIN(
            "TLS handshake of only ClientCertificate and Finished. No encryption is enabled and no "
                    + "key material is sent from the client. Uninitialized data might be used, or null keys. VerifyData is zeroed."),

    /**
     * TODO: Flows that send CRT out of order and still skip vrfy
     */
    /*
     * The following test cases require the integration of X509-Attacker. Hence
     * they've been postponed for now.
     */

    CRT_CKE_VRFY_CCS_FIN("TLS handshake that is completely valid. It's used to confirm that everything works."),
    /*
     * CRT1_CRT2_CKE_VRFY1_CCS_FIN(
     * "TLS handshake sending two certificate messages and afterwards only " +
     * "verifying the first."), CRT1_CRT2_CKE_VRFY2_CCS_FIN(
     * "TLS handshake sending two certificate messages and afterwards only " +
     * "verifying the second."), CRT1_CKE_CRT2_CKE2_VRFY1_CCS_FIN(
     * "TLS handshake sending two certificate messages and two client key " +
     * "exchanges. Beurdouche et al. reported that the JSSE state machine allows to send ClientCertificate "
     * +
     * "messages after a ClientKeyExchange. It is unclear if this behavior is exploitable and which certificate "
     * +
     * "will be consumed. Maybe it's possible to use the unverified certificate."
     * ), CRT1_CKE_CRT2_CKE2_VRFY2_CCS_FIN(
     * "TLS handshake sending two certificate messages and two client key " +
     * "exchanges. Beurdouche et al. reported that the JSSE state machine allows to send ClientCertificate "
     * +
     * "messages after a ClientKeyExchange. It is unclear if this behavior is exploitable and which certificate "
     * +
     * "will be consumed. Maybe it's possible to use the unverified certificate."
     * ),
     */

    ;

    String description;

    CcaWorkflowType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
