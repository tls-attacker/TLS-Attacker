/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.EchClientHelloType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "ClientHello")
public class ClientHelloMessage extends CoreClientHelloMessage<ClientHelloMessage> {

    public ClientHelloMessage() {
        super();
    }

    public ClientHelloMessage(Config tlsConfig) {
        super(tlsConfig);
        if (tlsConfig.isAddEncryptedClientHelloExtension()) {
            addExtension(new EncryptedClientHelloExtensionMessage(EchClientHelloType.INNER));
        }
    }

    @Override
    public ClientHelloHandler getHandler(TlsContext tlsContext) {
        return new ClientHelloHandler(tlsContext);
    }

    @Override
    public ClientHelloParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ClientHelloParser(stream, tlsContext);
    }

    @Override
    public ClientHelloPreparator getPreparator(TlsContext tlsContext) {
        return new ClientHelloPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ClientHelloSerializer getSerializer(TlsContext tlsContext) {
        return new ClientHelloSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }
}
