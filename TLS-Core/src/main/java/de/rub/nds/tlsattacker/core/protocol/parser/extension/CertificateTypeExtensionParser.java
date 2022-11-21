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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;

public class CertificateTypeExtensionParser extends ExtensionParser<CertificateTypeExtensionMessage> {

    public CertificateTypeExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(CertificateTypeExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() != 1) {
            msg.setCertificateTypesLength(parseIntField(ExtensionByteLength.CERTIFICATE_TYPE_TYPE_LENGTH));
            msg.setCertificateTypes(parseByteArrayField(msg.getCertificateTypesLength().getValue()));
        } else {
            msg.setCertificateTypes(parseByteArrayField(ExtensionByteLength.CERTIFICATE_TYPE_TYPE_LENGTH));
        }
    }

    @Override
    protected CertificateTypeExtensionMessage createExtensionMessage() {
        return new CertificateTypeExtensionMessage();
    }

}
