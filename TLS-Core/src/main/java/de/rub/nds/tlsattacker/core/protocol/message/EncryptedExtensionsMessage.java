/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.EncryptedExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EncryptedExtensionsParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EncryptedExtensionsPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedExtensionsSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "EncryptedExtensions")
public class EncryptedExtensionsMessage extends HandshakeMessage {

    public EncryptedExtensionsMessage() {
        super(HandshakeMessageType.ENCRYPTED_EXTENSIONS);
    }

    public EncryptedExtensionsMessage(Config config) {
        super(config, HandshakeMessageType.ENCRYPTED_EXTENSIONS);
        if (config.isAddRecordSizeLimitExtension()) {
            addExtension(new RecordSizeLimitExtensionMessage());
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("EncryptedExtensionMessage:");
        sb.append("\n  Extensions: ");
        if (getExtensions() == null) {
            sb.append("null");
        } else {
            for (ExtensionMessage e : getExtensions()) {
                sb.append(e.toString());
            }
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "EEM";
    }

    @Override
    public EncryptedExtensionsHandler getHandler(TlsContext context) {
        return new EncryptedExtensionsHandler(context);
    }

    @Override
    public EncryptedExtensionsParser getParser(TlsContext tlsContext, InputStream stream) {
        return new EncryptedExtensionsParser(stream, tlsContext);
    }

    @Override
    public EncryptedExtensionsPreparator getPreparator(TlsContext tlsContext) {
        return new EncryptedExtensionsPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public EncryptedExtensionsSerializer getSerializer(TlsContext tlsContext) {
        return new EncryptedExtensionsSerializer(this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

}
