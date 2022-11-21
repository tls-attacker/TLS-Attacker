/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.TrustedCaIndicationIdentifierType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TrustedCaIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TrustedCaIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TrustedCaIndicationExtensionPreparator extends ExtensionPreparator<TrustedCaIndicationExtensionMessage> {

    private final TrustedCaIndicationExtensionMessage msg;

    private static final Logger LOGGER = LogManager.getLogger();

    public TrustedCaIndicationExtensionPreparator(Chooser chooser, TrustedCaIndicationExtensionMessage message,
        TrustedCaIndicationExtensionSerializer serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setTrustedAuthorities(chooser.getConfig().getTrustedCaIndicationExtensionAuthorities());
        int taLength = 0;
        for (TrustedAuthority ta : msg.getTrustedAuthorities()) {
            TrustedAuthorityPreparator preparator = new TrustedAuthorityPreparator(chooser, ta);
            preparator.prepare();
            taLength += getLength(ta);
        }
        msg.setTrustedAuthoritiesLength(taLength);
    }

    public int getLength(TrustedAuthority authority) {
        TrustedCaIndicationIdentifierType type =
            TrustedCaIndicationIdentifierType.getIdentifierByByte(authority.getIdentifierType().getValue());
        if (type != null) {
            switch (type) {
                case PRE_AGREED:
                    return ExtensionByteLength.TRUSTED_AUTHORITY_TYPE;
                case KEY_SHA1_HASH:
                    return ExtensionByteLength.TRUSTED_AUTHORITY_HASH;
                case X509_NAME:
                    return (ExtensionByteLength.TRUSTED_AUTHORITY_DISTINGUISHED_NAME_LENGTH
                        + authority.getDistinguishedNameLength().getValue());
                case CERT_SHA1_HASH:
                    return ExtensionByteLength.TRUSTED_AUTHORITY_HASH;
                default:
                    return 0;

            }
        } else {
            LOGGER.warn("Could not find type. Using 0 length instead");
            return 0;
        }

    }

}
