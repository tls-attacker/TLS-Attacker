/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class CertificateStatusRequestV2ExtensionHandler
        extends ExtensionHandler<CertificateStatusRequestV2ExtensionMessage> {

    public CertificateStatusRequestV2ExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(CertificateStatusRequestV2ExtensionMessage message) {
        context.setStatusRequestV2RequestList(message.getStatusRequestList());
    }

}
