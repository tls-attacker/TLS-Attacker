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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class CertificateStatusRequestV2ExtensionParser
        extends ExtensionParser<CertificateStatusRequestV2ExtensionMessage> {

    public CertificateStatusRequestV2ExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(CertificateStatusRequestV2ExtensionMessage msg) {
        msg.setStatusRequestListLength(
                parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_LIST));

        msg.setStatusRequestBytes(parseByteArrayField(msg.getStatusRequestListLength().getValue()));
        ByteArrayInputStream innerStream =
                new ByteArrayInputStream(msg.getStatusRequestBytes().getValue());

        List<RequestItemV2> itemList = new LinkedList<>();
        while (innerStream.available() > 0) {
            RequestItemV2Parser parser = new RequestItemV2Parser(innerStream);
            RequestItemV2 item = new RequestItemV2();
            parser.parse(item);
            itemList.add(item);
        }
        msg.setStatusRequestList(itemList);
    }
}
