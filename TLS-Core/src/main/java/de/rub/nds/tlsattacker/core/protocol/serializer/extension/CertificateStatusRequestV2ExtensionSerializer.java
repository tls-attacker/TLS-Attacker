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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;

public class CertificateStatusRequestV2ExtensionSerializer extends
        ExtensionSerializer<CertificateStatusRequestV2ExtensionMessage> {

    private final CertificateStatusRequestV2ExtensionMessage msg;

    public CertificateStatusRequestV2ExtensionSerializer(CertificateStatusRequestV2ExtensionMessage message) {
        super(message);
        msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(msg.getStatusRequestListLength().getValue(), ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_LIST);

        for (RequestItemV2 item : msg.getStatusRequestList()) {
            RequestItemV2Serializer serializer = new RequestItemV2Serializer(item);
            appendBytes(serializer.serialize());
        }

        return getAlreadySerialized();
    }

}
