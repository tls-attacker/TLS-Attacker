/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import jakarta.xml.bind.annotation.adapters.XmlAdapter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.tls.Certificate;

public class CertificateAdapter extends XmlAdapter<String, Certificate> {

    @Override
    public Certificate unmarshal(String v) throws Exception {

        Certificate cert =
                Certificate.parse(
                        new ByteArrayInputStream(
                                ArrayConverter.hexStringToByteArray(v.replaceAll("\\s+", ""))));
        return cert;
    }

    @Override
    public String marshal(Certificate v) throws Exception {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        v.encode(outStream);
        return ArrayConverter.bytesToHexString(outStream.toByteArray());
    }
}
