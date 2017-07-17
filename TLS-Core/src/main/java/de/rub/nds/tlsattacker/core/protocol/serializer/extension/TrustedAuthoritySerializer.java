/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.TrustedCaIndicationIdentifierType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TrustedAuthoritySerializer extends Serializer<TrustedAuthority> {

    private final TrustedAuthority trustedAuthority;

    public TrustedAuthoritySerializer(TrustedAuthority trustedAuthority) {
        this.trustedAuthority = trustedAuthority;
    }

    @Override
    protected byte[] serializeBytes() {

        switch (TrustedCaIndicationIdentifierType.getIdentifierByByte(trustedAuthority.getIdentifierType().getValue())) {
            case PRE_AGREED:
                appendByte(trustedAuthority.getIdentifierType().getValue());
                break;
            case KEY_SHA1_HASH:
                appendByte(trustedAuthority.getIdentifierType().getValue());
                appendBytes(trustedAuthority.getSha1Hash().getValue());
                break;
            case X509_NAME:
                appendByte(trustedAuthority.getIdentifierType().getValue());
                appendInt(trustedAuthority.getDistinguishedNameLength().getValue(),
                        ExtensionByteLength.TRUSTED_AUTHORITY_DISTINGUISHED_NAME_LENGTH);
                appendBytes(trustedAuthority.getDistinguishedName().getValue());
                break;
            case CERT_SHA1_HASH:
                appendByte(trustedAuthority.getIdentifierType().getValue());
                appendBytes(trustedAuthority.getSha1Hash().getValue());
                break;
            default:
                break;
        }
        return getAlreadySerialized();
    }

}
