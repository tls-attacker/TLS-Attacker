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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.EncryptedExtensionsHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EncryptedExtensionsParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EncryptedExtensionsPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedExtensionsSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

@XmlRootElement(name = "EncryptedExtensions")
public class EncryptedExtensionsMessage extends HandshakeMessage<EncryptedExtensionsMessage> {

    public EncryptedExtensionsMessage() {
        super(HandshakeMessageType.ENCRYPTED_EXTENSIONS);
    }

    public EncryptedExtensionsMessage(Config config) {
        super(HandshakeMessageType.ENCRYPTED_EXTENSIONS);
        if (!config.isRespectClientProposedExtensions()) {
            createConfiguredExtensions(config).forEach(this::addExtension);
        }
    }

    @Override
    public final List<ExtensionMessage> createConfiguredExtensions(Config config) {
        List<ExtensionMessage> configuredExtensions = new LinkedList<>();
        if (config.isAddRecordSizeLimitExtension()) {
            configuredExtensions.add(new RecordSizeLimitExtensionMessage());
        }
        return configuredExtensions;
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
    public EncryptedExtensionsHandler getHandler(TlsContext tlsContext) {
        return new EncryptedExtensionsHandler(tlsContext);
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
        return new EncryptedExtensionsSerializer(this);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final EncryptedExtensionsMessage other = (EncryptedExtensionsMessage) obj;
        if (!Objects.equals(this.getExtensions(), other.getExtensions())) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        return hash;
    }
}
