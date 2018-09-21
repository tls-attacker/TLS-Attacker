/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.TrustedCaIndicationIdentifierType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TrustedAuthorityParser extends Parser<TrustedAuthority> {

    private static final Logger LOGGER = LogManager.getLogger();

    public TrustedAuthorityParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public TrustedAuthority parse() {
        TrustedAuthority authority = new TrustedAuthority();
        authority.setIdentifierType(parseByteField(ExtensionByteLength.TRUSTED_AUTHORITY_TYPE));

        switch (TrustedCaIndicationIdentifierType.getIdentifierByByte(authority.getIdentifierType().getValue())) {
            case PRE_AGREED:
                // nothing to do here
                break;
            case CERT_SHA1_HASH:// fall through
            case KEY_SHA1_HASH:
                authority.setSha1Hash(parseByteArrayField(ExtensionByteLength.TRUSTED_AUTHORITY_HASH));
                break;
            case X509_NAME:
                authority
                        .setDistinguishedNameLength(parseIntField(ExtensionByteLength.TRUSTED_AUTHORITY_DISTINGUISHED_NAME_LENGTH));
                authority.setDistinguishedName(parseByteArrayField(authority.getDistinguishedNameLength().getValue()));
                break;
            default:
                LOGGER.warn("Couldn't set the trusted authority to reasonable values");
                break;
        }

        return authority;
    }

}
