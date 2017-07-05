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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CertificateTypeExtensionSerializer extends ExtensionSerializer<CertificateTypeExtensionMessage> {

    private final CertificateTypeExtensionMessage msg;

    public CertificateTypeExtensionSerializer(CertificateTypeExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        if (msg.getIsClientMessage().getValue()) {
            appendInt(msg.getCertificateTypesLength().getValue(),
                    ExtensionByteLength.CERTIFICATE_TYPE_EXTENSION_TYPES_LENGTHFIELD_LENGTH);
            appendBytes(msg.getCertificateTypes().getValue());
        } else {
            appendBytes(msg.getCertificateTypes().getValue());
        }

        return getAlreadySerialized();
    }

}
