/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import java.util.Objects;

public class ServerCertificateTypeExtensionSerializer
    extends ExtensionSerializer<ServerCertificateTypeExtensionMessage> {

    private final ServerCertificateTypeExtensionMessage msg;

    public ServerCertificateTypeExtensionSerializer(ServerCertificateTypeExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        if (Objects.equals(msg.getIsClientMessage().getValue(), Boolean.TRUE)) {
            appendInt(msg.getCertificateTypesLength().getValue(), ExtensionByteLength.CERTIFICATE_TYPE_TYPE_LENGTH);
        }
        appendBytes(msg.getCertificateTypes().getValue());

        return getAlreadySerialized();
    }
}
