/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificatePairSerializer extends Serializer<CertificatePair> {

    private final CertificatePair pair;

    public CertificatePairSerializer(CertificatePair pair) {
        this.pair = pair;
    }

    @Override
    protected byte[] serializeBytes() {
        appendInt(pair.getCertificateLength().getValue(), HandshakeByteLength.CERTIFICATE_LENGTH);
        appendBytes(pair.getCertificate().getValue());
        appendInt(pair.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        appendBytes(pair.getExtensions().getValue());
        return getAlreadySerialized();
    }

}
