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
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

public class TrustedAuthoritySerializer extends Serializer<TrustedAuthority> {

    private final TrustedAuthority trustedAuthority;

    public TrustedAuthoritySerializer(TrustedAuthority trustedAuthority) {
        this.trustedAuthority = trustedAuthority;
    }

    @Override
    protected byte[] serializeBytes() {
        if (trustedAuthority.getIdentifierType() != null && trustedAuthority.getIdentifierType().getValue() != null) {
            appendByte(trustedAuthority.getIdentifierType().getValue());
        }
        if (trustedAuthority.getSha1Hash() != null && trustedAuthority.getSha1Hash().getValue() != null) {
            appendBytes(trustedAuthority.getSha1Hash().getValue());
        }
        if (trustedAuthority.getDistinguishedNameLength() != null
                && trustedAuthority.getDistinguishedNameLength().getValue() != null) {
            appendInt(trustedAuthority.getDistinguishedNameLength().getValue(),
                    ExtensionByteLength.TRUSTED_AUTHORITY_DISTINGUISHED_NAME_LENGTH);
        }
        if (trustedAuthority.getDistinguishedName() != null
                && trustedAuthority.getDistinguishedName().getValue() != null) {
            appendBytes(trustedAuthority.getDistinguishedName().getValue());
        }

        return getAlreadySerialized();
    }

}
