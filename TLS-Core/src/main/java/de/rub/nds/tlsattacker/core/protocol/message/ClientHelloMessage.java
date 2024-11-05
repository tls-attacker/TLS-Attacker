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
import de.rub.nds.tlsattacker.core.protocol.handler.ClientHelloHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "ClientHello")
public class ClientHelloMessage extends CoreClientHelloMessage {

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
    public ClientHelloHandler getHandler(Context context) {
        return new ClientHelloHandler(context.getTlsContext());
    }

    @Override
    public ClientHelloParser getParser(Context context, InputStream stream) {
        return new ClientHelloParser(stream, context.getTlsContext());
    }

    @Override
    public ClientHelloPreparator getPreparator(Context context) {
        return new ClientHelloPreparator(context.getChooser(), this);
    }

    @Override
    public ClientHelloSerializer getSerializer(Context context) {
        return new ClientHelloSerializer(this, context.getChooser().getSelectedProtocolVersion());
    }
}
