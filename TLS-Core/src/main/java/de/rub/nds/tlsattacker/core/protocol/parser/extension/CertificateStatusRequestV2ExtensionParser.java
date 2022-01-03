/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import java.util.LinkedList;
import java.util.List;

public class CertificateStatusRequestV2ExtensionParser
    extends ExtensionParser<CertificateStatusRequestV2ExtensionMessage> {

    public CertificateStatusRequestV2ExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(CertificateStatusRequestV2ExtensionMessage msg) {
        msg.setStatusRequestListLength(parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_V2_LIST));
        msg.setStatusRequestBytes(parseByteArrayField(msg.getStatusRequestListLength().getValue()));

        int pointer = 0;
        List<RequestItemV2> itemList = new LinkedList<>();
        while (pointer < msg.getStatusRequestBytes().getValue().length) {
            RequestItemV2Parser parser = new RequestItemV2Parser(pointer, msg.getStatusRequestBytes().getValue());
            itemList.add(parser.parse());
            if (pointer == parser.getPointer()) {
                throw new ParserException("Ran into infinite Loop while parsing RequestItemV2");
            }
            pointer = parser.getPointer();
        }
        msg.setStatusRequestList(itemList);
    }

    @Override
    protected CertificateStatusRequestV2ExtensionMessage createExtensionMessage() {
        return new CertificateStatusRequestV2ExtensionMessage();
    }

}
