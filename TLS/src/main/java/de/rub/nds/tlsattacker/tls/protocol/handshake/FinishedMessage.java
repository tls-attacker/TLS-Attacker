/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class FinishedMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    ModifiableByteArray verifyData;

    public FinishedMessage() {
	super(HandshakeMessageType.FINISHED);
    }

    public FinishedMessage(ConnectionEnd messageIssuer) {
	super(HandshakeMessageType.FINISHED);
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByteArray getVerifyData() {
	return verifyData;
    }

    public void setVerifyData(ModifiableByteArray verifyData) {
	this.verifyData = verifyData;
    }

    public void setVerifyData(byte[] value) {
	this.verifyData = ModifiableVariableFactory.safelySetValue(this.verifyData, value);
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nFinished message:").append(super.toString()).append("\n  Verify Data: ")
		.append(ArrayConverter.bytesToHexString(verifyData.getValue()));
	return sb.toString();
    }
}
