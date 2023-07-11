/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.Version;

public class OcspTbsRequest extends Asn1Sequence {

    private Version version; // Explicit, DEFAULT v1

    private GeneralName requestorName; // Explicit, OPTIONAL

    private OcspRequestList requestList; // Sequence of Requests

    private OcspRequestExtensions requestExtensions; // EXPLICIT Optional

    public OcspTbsRequest(String identifier) {
        super(identifier);
        version = new Version("version");
        requestorName = new GeneralName("requestorName");
        requestList = new OcspRequestList("requestList");
        requestExtensions = new OcspRequestExtensions("requestExtensions");
    }

    public Version getVersion() {
        return version;
    }

    public void setVersion(Version version) {
        this.version = version;
    }

    public GeneralName getRequestorName() {
        return requestorName;
    }

    public void setRequestorName(GeneralName requestorName) {
        this.requestorName = requestorName;
    }

    public OcspRequestList getRequestList() {
        return requestList;
    }

    public void setRequestList(OcspRequestList requestList) {
        this.requestList = requestList;
    }

    public OcspRequestExtensions getRequestExtensions() {
        return requestExtensions;
    }

    public void setRequestExtensions(OcspRequestExtensions requestExtensions) {
        this.requestExtensions = requestExtensions;
    }
}
