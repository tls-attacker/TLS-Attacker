/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestV2ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateStatusRequestV2ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestV2ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class CertificateStatusRequestV2ExtensionHandler extends
        ExtensionHandler<CertificateStatusRequestV2ExtensionMessage> {

    public CertificateStatusRequestV2ExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public CertificateStatusRequestV2ExtensionParser getParser(byte[] message, int pointer) {
        return new CertificateStatusRequestV2ExtensionParser(pointer, message);
    }

    @Override
    public CertificateStatusRequestV2ExtensionPreparator getPreparator(
            CertificateStatusRequestV2ExtensionMessage message) {
        return new CertificateStatusRequestV2ExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public CertificateStatusRequestV2ExtensionSerializer getSerializer(
            CertificateStatusRequestV2ExtensionMessage message) {
        return new CertificateStatusRequestV2ExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(CertificateStatusRequestV2ExtensionMessage message) {
        context.setStatusRequestV2RequestList(message.getStatusRequestList());
    }

}
