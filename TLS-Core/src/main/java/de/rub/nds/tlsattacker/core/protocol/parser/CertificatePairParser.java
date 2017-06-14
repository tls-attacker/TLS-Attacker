/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificatePairParser extends Parser<CertificatePair> {

    public CertificatePairParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public CertificatePair parse() {
        CertificatePair pair = new CertificatePair();
        pair.setCertificateLength(parseIntField(HandshakeByteLength.CERTIFICATE_LENGTH));
        pair.setCertificate(parseByteArrayField(pair.getCertificateLength().getValue()));
        pair.setExtensionsLength(parseIntField(HandshakeByteLength.EXTENSION_LENGTH));
        pair.setExtensions(parseByteArrayField(pair.getExtensionsLength().getValue()));
        return pair;
    }

}
