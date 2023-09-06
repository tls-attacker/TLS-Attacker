/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.model.Asn1Sequence;

public class OcspResponseBytes extends Asn1Sequence {

    private Asn1ObjectIdentifier responseType;
    private Asn1OctetString response;

    public OcspResponseBytes(String identifier) {
        super(identifier);
        responseType = new Asn1ObjectIdentifier("responseType");
        response = new Asn1OctetString("response");
    }
}
