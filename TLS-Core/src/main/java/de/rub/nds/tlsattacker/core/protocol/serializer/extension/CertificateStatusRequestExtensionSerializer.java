/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.intToBytes;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;

public class CertificateStatusRequestExtensionSerializer extends
        ExtensionSerializer<CertificateStatusRequestExtensionMessage> {

    private final CertificateStatusRequestExtensionMessage message;

    public CertificateStatusRequestExtensionSerializer(CertificateStatusRequestExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(intToBytes(message.getCertificateStatusRequestType().getValue(),
                ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_STATUS_TYPE));
        appendBytes(intToBytes(message.getResponderIDListLength().getValue(),
                ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_RESPONDER_ID_LIST_LENGTH));
        appendBytes(message.getResponderIDList().getValue());
        appendBytes(intToBytes(message.getRequestExtensionLength().getValue(),
                ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_REQUEST_EXTENSION_LENGTH));
        appendBytes(message.getRequestExtension().getValue());

        return getAlreadySerialized();
    }

}
