/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerVerifyHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.SSL2ServerVerifyParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ServerVerifyPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Objects;

@SuppressWarnings("serial")
@XmlRootElement(name = "SSL2ServerVerify")
public class SSL2ServerVerifyMessage extends SSL2Message {

    // TODO, nit: The type byte is encrypted for ServerVerify messages.
    @ModifiableVariableProperty private ModifiableByteArray encryptedPart;

    public SSL2ServerVerifyMessage() {
        super(SSL2MessageType.SSL_SERVER_VERIFY);
        this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
    }

    @Override
    public String toCompactString() {
        return "SSL2 ServerVerify Message";
    }

    @Override
    public String toShortString() {
        return "SSL2_SV";
    }

    @Override
    public SSL2ServerVerifyHandler getHandler(TlsContext tlsContext) {
        return new SSL2ServerVerifyHandler(tlsContext);
    }

    @Override
    public SSL2ServerVerifyParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SSL2ServerVerifyParser(stream, tlsContext);
    }

    @Override
    public SSL2ServerVerifyPreparator getPreparator(TlsContext tlsContext) {
        return new SSL2ServerVerifyPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ProtocolMessageSerializer<SSL2ServerVerifyMessage> getSerializer(TlsContext tlsContext) {
        // We currently don't send ServerVerify messages, only receive them.
        return null;
    }

    public ModifiableByteArray getEncryptedPart() {
        return encryptedPart;
    }

    public void setEncryptedPart(ModifiableByteArray encryptedPart) {
        this.encryptedPart = encryptedPart;
    }

    public void setEncryptedPart(byte[] encryptedPart) {
        this.encryptedPart =
                ModifiableVariableFactory.safelySetValue(this.encryptedPart, encryptedPart);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + Objects.hashCode(this.encryptedPart);
        return hash;
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
        final SSL2ServerVerifyMessage other = (SSL2ServerVerifyMessage) obj;
        return Objects.equals(this.encryptedPart, other.encryptedPart);
    }
}
