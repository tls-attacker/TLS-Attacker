/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.TrustedCaIndicationIdentifierType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TrustedCaIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class TrustedCaIndicationExtensionPreparator extends ExtensionPreparator<TrustedCaIndicationExtensionMessage> {

    private final TrustedCaIndicationExtensionMessage msg;

    public TrustedCaIndicationExtensionPreparator(Chooser chooser, TrustedCaIndicationExtensionMessage message,
            TrustedCaIndicationExtensionSerializer serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setTrustedAuthorities(chooser.getConfig().getTrustedCaIndicationExtensionAuthorties());
        int taLength = 0;
        for (TrustedAuthority ta : msg.getTrustedAuthorities()) {
            TrustedAuthorityPreparator preparator = new TrustedAuthorityPreparator(chooser, ta);
            preparator.prepare();
            taLength += getLength(ta);
        }
        msg.setTrustedAuthoritiesLength(taLength);
    }

    public int getLength(TrustedAuthority authority) {

        switch (TrustedCaIndicationIdentifierType.getIdentifierByByte(authority.getIdentifierType().getValue())) {
            case PRE_AGREED:
                return ExtensionByteLength.TRUSTED_AUTHORITY_TYPE;
            case KEY_SHA1_HASH:
                return ExtensionByteLength.TRUSTED_AUTHORITY_HASH;
            case X509_NAME:
                return (ExtensionByteLength.TRUSTED_AUTHORITY_DISTINGUISHED_NAME_LENGTH + authority
                        .getDistinguishedNameLength().getValue());
            case CERT_SHA1_HASH:
                return ExtensionByteLength.TRUSTED_AUTHORITY_HASH;
            default:
                return 0;

        }

    }

}
