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
import de.rub.nds.tlsattacker.core.protocol.message.extension.certificatestatusrequestitemv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.certificatestatusrequestitemv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RequestItemV2Preparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ResponderIdPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class RequestItemV2Serializer extends Serializer<RequestItemV2> {

    private final RequestItemV2 reqItem;

    public RequestItemV2Serializer(RequestItemV2 reqItem) {
        this.reqItem = reqItem;
    }

    @Override
    protected byte[] serializeBytes() {
        RequestItemV2Preparator preparator = new RequestItemV2Preparator(new TlsContext().getChooser(), reqItem);
        preparator.prepare();
        appendInt(reqItem.getRequestType().getValue(), ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_STATUS_TYPE);
        appendInt(reqItem.getRequestLength().getValue(),
                ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_REQUEST_LENGTH);
        appendInt(reqItem.getResponderIdListLength().getValue(),
                ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_RESPONDER_ID);

        for (ResponderId id : reqItem.getResponderIdList()) {
            ResponderIdPreparator preparatorResponderId = new ResponderIdPreparator(new TlsContext().getChooser(), id);
            preparatorResponderId.prepare();
            ResponderIdSerializer serializer = new ResponderIdSerializer(id);
            appendBytes(serializer.serialize());
        }

        appendInt(reqItem.getRequestExtensionsLength().getValue(),
                ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_REQUEST_EXTENSION);
        appendBytes(reqItem.getRequestExtensions().getValue());

        return getAlreadySerialized();
    }

}
