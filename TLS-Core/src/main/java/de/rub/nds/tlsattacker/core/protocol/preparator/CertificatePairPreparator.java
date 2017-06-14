/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificatePairPreparator extends Preparator<CertificatePair> {

    private final CertificatePair pair;

    public CertificatePairPreparator(TlsContext context, CertificatePair pair) {
        super(context, pair);
        this.pair = pair;
    }

    @Override
    public void prepare() {
        pair.setCertificate(pair.getCertificateConfig());
        pair.setCertificateLength(pair.getCertificate().getValue().length);
        pair.setExtensions(pair.getExtensionsConfig());
        pair.setExtensionsLength(pair.getExtensions().getValue().length);
    }

}