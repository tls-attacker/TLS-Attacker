/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;


public class CertificatePairSerializer extends Serializer<CertificatePair> {

    private final CertificatePair pair;

    public CertificatePairSerializer(CertificatePair pair) {
        this.pair = pair;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing CertificatePair");
        writeCertificateLength(pair);
        writeCertificate(pair);
        if (pair.getExtensions() != null) {
            writeExtensionsLength(pair);
            writeExtensions(pair);
        }
        return getAlreadySerialized();
    }

    private void writeCertificateLength(CertificatePair pair) {
        appendInt(pair.getCertificateLength().getValue(), HandshakeByteLength.CERTIFICATE_LENGTH);
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    private void writeCertificate(CertificatePair pair) {
        appendBytes(pair.getCertificate().getValue());
        LOGGER.debug("Certificate: " + ArrayConverter.bytesToHexString(pair.getCertificate().getValue()));
    }

    private void writeExtensionsLength(CertificatePair pair) {
        appendInt(pair.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        LOGGER.debug("ExtensionsLength: " + pair.getExtensionsLength().getValue());
    }

    private void writeExtensions(CertificatePair pair) {
        appendBytes(pair.getExtensions().getValue());
        LOGGER.debug("Extensions: " + ArrayConverter.bytesToHexString(pair.getExtensions().getValue()));
    }

}
