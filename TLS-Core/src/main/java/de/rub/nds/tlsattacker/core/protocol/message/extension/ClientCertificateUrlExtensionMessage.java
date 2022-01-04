/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ClientCertificateUrlExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientCertificateUrlExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ClientCertificateUrlExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientCertificateUrlExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

public class ClientCertificateUrlExtensionMessage extends ExtensionMessage<ClientCertificateUrlExtensionMessage> {
@XmlRootElement(name = "ClientCertificateUrlExtension")
public class ClientCertificateUrlExtensionMessage extends ExtensionMessage {

    public ClientCertificateUrlExtensionMessage() {
        super(ExtensionType.CLIENT_CERTIFICATE_URL);
    }

    public ClientCertificateUrlExtensionMessage(Config config) {
        super(ExtensionType.CLIENT_CERTIFICATE_URL);
    }

    @Override
    public ClientCertificateUrlExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ClientCertificateUrlExtensionParser(stream, tlsContext.getConfig());
    }

    @Override
    public ClientCertificateUrlExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new ClientCertificateUrlExtensionPreparator(tlsContext.getChooser(), this, getSerializer(tlsContext));
    }

    @Override
    public ClientCertificateUrlExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new ClientCertificateUrlExtensionSerializer(this);
    }

    @Override
    public ClientCertificateUrlExtensionHandler getHandler(TlsContext tlsContext) {
        return new ClientCertificateUrlExtensionHandler(tlsContext);
    }

}
