/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1Sequence;
import java.util.List;

public class OcspRequestList extends Asn1Sequence {

    private List<OcspRequest> requestList;

    public OcspRequestList(String identifier) {
        super(identifier);
    }

    public List<OcspRequest> getRequestList() {
        return requestList;
    }

    public void setRequestList(List<OcspRequest> requestList) {
        this.requestList = requestList;
    }
}
