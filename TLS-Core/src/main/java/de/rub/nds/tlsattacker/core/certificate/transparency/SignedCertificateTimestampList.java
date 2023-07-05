/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import java.util.LinkedList;
import java.util.List;

public class SignedCertificateTimestampList {
    private byte[] encodedTimestampList;
    private List<SignedCertificateTimestamp> certificateTimestampList;

    public SignedCertificateTimestampList() {
        certificateTimestampList = new LinkedList<>();
    }

    public byte[] getEncodedTimestampList() {
        return encodedTimestampList;
    }

    public void setEncodedTimestampList(byte[] encodedTimestampList) {
        this.encodedTimestampList = encodedTimestampList;
    }

    public List<SignedCertificateTimestamp> getCertificateTimestampList() {
        return certificateTimestampList;
    }
}
