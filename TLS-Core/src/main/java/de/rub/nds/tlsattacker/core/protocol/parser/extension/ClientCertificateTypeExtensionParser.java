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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;

public class ClientCertificateTypeExtensionParser extends ExtensionParser<ClientCertificateTypeExtensionMessage> {

    public ClientCertificateTypeExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(ClientCertificateTypeExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() != 1) {
            msg.setCertificateTypesLength(parseIntField(ExtensionByteLength.CERTIFICATE_TYPE_TYPE_LENGTH));
            msg.setCertificateTypes(parseByteArrayField(msg.getCertificateTypesLength().getValue()));
        } else {
            msg.setCertificateTypes(parseByteArrayField(ExtensionByteLength.CERTIFICATE_TYPE_TYPE_LENGTH));
        }
    }

    @Override
    protected ClientCertificateTypeExtensionMessage createExtensionMessage() {
        return new ClientCertificateTypeExtensionMessage();
    }

}
