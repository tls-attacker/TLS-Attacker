/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;

import java.util.LinkedList;
import java.util.List;

public class CcaCertificateGenerator {

    /**
     *
     * @param ccaDelegate
     * @param type
     * @return TODO: I might need access to a trust store. Or seperate
     *         directories for keys and certificates. It's likely that TODO: any
     *         integration of multiple certificates, partially with keys, will
     *         be implemented with x509 attacker.
     */
    public static CertificateMessage generateCertificate(CcaDelegate ccaDelegate, CcaCertificateType type) {
        CertificateMessage certificateMessage = new CertificateMessage();
        if (type != null) {
            switch (type) {
                case CLIENT_INPUT:
                    List<CertificatePair> certificatePairsList = new LinkedList<>();
                    CertificatePair certificatePair = new CertificatePair(ccaDelegate.getClientCertificate());
                    certificatePairsList.add(certificatePair);
                    certificateMessage.setCertificatesList(certificatePairsList);
                    break;
                case EMPTY:
                    certificateMessage.setCertificatesListBytes(Modifiable.explicit(new byte[0]));
                    break;
                default:
                    break;
            }
        }
        return certificateMessage;
    }
}
