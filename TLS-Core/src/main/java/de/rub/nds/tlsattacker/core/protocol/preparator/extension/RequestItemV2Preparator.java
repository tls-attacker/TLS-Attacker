/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class RequestItemV2Preparator extends Preparator<RequestItemV2> {

    private final RequestItemV2 item;

    public RequestItemV2Preparator(Chooser chooser, RequestItemV2 object) {
        super(chooser, object);
        item = object;
    }

    @Override
    public void prepare() {
        item.setRequestType(item.getRequestTypeConfig());
        item.setRequestLength(item.getRequestLengthConfig());
        item.setResponderIdListLength(item.getResponderIdListLengthConfig());
        item.setRequestExtensionsLength(item.getRequestExtensionLengthConfig());
        item.setRequestExtensions(item.getRequestExtensionsConfig());
    }

}
