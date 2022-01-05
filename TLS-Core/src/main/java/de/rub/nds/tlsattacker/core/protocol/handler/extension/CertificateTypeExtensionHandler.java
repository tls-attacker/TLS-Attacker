/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateTypeExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateTypeExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateTypeExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class CertificateTypeExtensionHandler extends ExtensionHandler<CertificateTypeExtensionMessage> {

    public CertificateTypeExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public CertificateTypeExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new CertificateTypeExtensionParser(pointer, message, config);
    }

    @Override
    public CertificateTypeExtensionPreparator getPreparator(CertificateTypeExtensionMessage message) {
        return new CertificateTypeExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public CertificateTypeExtensionSerializer getSerializer(CertificateTypeExtensionMessage message) {
        return new CertificateTypeExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(CertificateTypeExtensionMessage message) {
        context.setCertificateTypeDesiredTypes(
            CertificateType.getCertificateTypesAsList(message.getCertificateTypes().getValue()));
    }

}
