/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.cca;

public enum CcaWorkflowType {
    CRT_CKE_CCS_FIN("TLS handshake flow with CertificateVerify omitted.", true, false),
    CRT_CKE_FIN("TLS handshake flow with CertificateVerify and CCS omitted.", true, false),
    CRT_CKE_ZFIN("TLS handshake flow with CertificateVerify and CCS omitted. Additionally the verify_data "
        + "in the FinishedMessage is set zeroes only. Supposedly found in CyaSSL 3.2.0", true, false),
    CKE_CCS_FIN("TLS handshake completely ignoring the CertificateRequest. First seen in GnuTLS 3.3.9.", false, false),
    CKE_CCS_CRT_FIN_CCS_RND("Handshake abusing incorrect transitions in the JSSE state machine.", true, false),
    CRT_CCS_FIN("TLS handshake omitting the ClientKeyExchange and CertificateVerify. This might lead to null "
        + "keys or non deterministic keys being established. Additionally same state machines might be confused "
        + "leading to a ClientAuthentication bypass.", true, false),
    CRT_FIN("TLS handshake of only ClientCertificate and Finished. No encryption is enabled and no "
        + "key material is sent from the client. Uninitialized data might be used, or null keys.", true, false),
    CRT_ZFIN("TLS handshake of only ClientCertificate and Finished. No encryption is enabled and no "
        + "key material is sent from the client. Uninitialized data might be used, or null keys. "
        + "VerifyData is zeroed.", true, false),
    CRT_ECKE_CCS_FIN("TLS handshake flow with empty CKE message.", true, false),
    CKE_CRT_CCS_FIN("TLS handshake flow with CRT out of order and VRFY omitted.", true, false),
    CKE_CRT_VRFY_CCS_FIN("TLS handshake flow with CRT out of order.", true, true),
    CRT_CKE_VRFY_CCS_FIN("TLS handshake that is completely valid. It's used to confirm that everything works.", true,
        true),
    CRT1_CRT2_CKE_VRFY1_CCS_FIN("TLS handshake sending two certificate messages and afterwards only verifying "
        + "the first. The implementation ought to use the X509-Attacker generated certificate for the first and "
        + "the client provided for the second. If this testcase is true it indicates a potential vulnerability but "
        + "doesn't " + "signify one.", true, true),
    CRT1_CRT2_CKE_VRFY2_CCS_FIN("TLS handshake sending two certificate messages and afterwards only verifying "
        + "the second. The implementation ought to use the X509-Attacker generated certificate for the first and "
        + "the client provided for the second. If this testcase is true it indicates a potential vulnerability but "
        + "doesn't signify one.", true, true),
    CRT1_CKE_CRT2_CKE2_VRFY1_CCS_FIN("TLS handshake sending two certificate messages and two client key "
        + "exchanges. Beurdouche et al. reported that the JSSE state machine allows to send ClientCertificate "
        + "messages after a ClientKeyExchange. It is unclear if this behavior is exploitable and which certificate "
        + "will be consumed. Maybe it's possible to use the unverified certificate.", true, true),
    CRT1_CKE_CRT2_CKE2_VRFY2_CCS_FIN("TLS handshake sending two certificate messages and two client key "
        + "exchanges. Beurdouche et al. reported that the JSSE state machine allows to send ClientCertificate "
        + "messages after a ClientKeyExchange. It is unclear if this behavior is exploitable and which certificate "
        + "will be consumed. Maybe it's possible to use the unverified certificate.", true, true),
    CRT_VRFY_CKE_CCS_FIN("TLS handshake reordering VRFY and CKE", true, true),
    CRT_CKE_CCS_VRFY_FIN("TLS handshake reordering VRFY and CCS", true, true);

    private String description;
    private Boolean requiresCertificate;
    private Boolean requiresKey;

    CcaWorkflowType(String description, Boolean requiresCertificate, Boolean requiresKey) {
        this.description = description;
        this.requiresCertificate = requiresCertificate;
        this.requiresKey = requiresKey;
    }

    public String getDescription() {
        return description;
    }

    public Boolean getRequiresCertificate() {
        return this.requiresCertificate;
    }

    public Boolean getRequiresKey() {
        return this.requiresKey;
    }
}
