/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import java.util.Objects;

public class ClientCertificateTypeExtensionSerializer
        extends ExtensionSerializer<ClientCertificateTypeExtensionMessage> {

    private final ClientCertificateTypeExtensionMessage msg;

    public ClientCertificateTypeExtensionSerializer(ClientCertificateTypeExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        if (Objects.equals(msg.getIsClientMessage().getValue(), Boolean.TRUE)) {
            appendInt(
                    msg.getCertificateTypesLength().getValue(),
                    ExtensionByteLength.CERTIFICATE_TYPE_TYPE_LENGTH);
        }
        appendBytes(msg.getCertificateTypes().getValue());

        return getAlreadySerialized();
    }
}
