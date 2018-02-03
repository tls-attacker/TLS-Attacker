package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.SSL2ServerVerifyHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class SSL2ServerVerifyMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger messageLength;
	
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
	public ProtocolMessageHandler<SSL2ServerVerifyMessage> getHandler(TlsContext context) {
		return new SSL2ServerVerifyHandler(context);
	}

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength = ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
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
