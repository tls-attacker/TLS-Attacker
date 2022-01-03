/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerVerifyHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.SSL2ServerVerifyParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ServerVerifyPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

@SuppressWarnings("serial")
@XmlRootElement
public class SSL2ServerVerifyMessage extends SSL2HandshakeMessage {

    // TODO, nit: The type byte is encrypted for ServerVerify messages.
    @ModifiableVariableProperty
    private ModifiableByteArray encryptedPart;

    public SSL2ServerVerifyMessage() {
        super(HandshakeMessageType.SSL2_SERVER_VERIFY);
        this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
    }

    public SSL2ServerVerifyMessage(Config config) {
        this();
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
    public SSL2ServerVerifyHandler getHandler(TlsContext context) {
        return new SSL2ServerVerifyHandler(context);
    }

    @Override
    public SSL2ServerVerifyParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SSL2ServerVerifyParser(stream, tlsContext.getChooser().getSelectedProtocolVersion(), tlsContext);
    }

    @Override
    public SSL2ServerVerifyPreparator getPreparator(TlsContext tlsContext) {
        return new SSL2ServerVerifyPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public HandshakeMessageSerializer<SSL2ServerVerifyMessage> getSerializer(TlsContext tlsContext) {
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
        this.encryptedPart = ModifiableVariableFactory.safelySetValue(this.encryptedPart, encryptedPart);
    }

}
