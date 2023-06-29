/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class RequestItemV2Parser extends Parser<RequestItemV2> {

    public RequestItemV2Parser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(RequestItemV2 item) {
        item.setRequestType(
                parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_STATUS_TYPE));
        item.setRequestLength(
                parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_REQUEST_LENGTH));
        item.setResponderIdListLength(
                parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_RESPONDER_ID));
        item.setResponderIdListBytes(
                parseByteArrayField(item.getResponderIdListLength().getValue()));
        item.setRequestExtensionsLength(
                parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_REQUEST_EXTENSION));
        item.setRequestExtensions(
                parseByteArrayField(item.getRequestExtensionsLength().getValue()));

        List<ResponderId> responderIds = new LinkedList<>();
        ByteArrayInputStream innerStream =
                new ByteArrayInputStream(item.getResponderIdListBytes().getValue());
        while (innerStream.available() > 0) {
            ResponderIdParser parser = new ResponderIdParser(innerStream);
            ResponderId id = new ResponderId();
            parser.parse(id);
            responderIds.add(id);
        }
        item.setResponderIdList(responderIds);
    }
}
