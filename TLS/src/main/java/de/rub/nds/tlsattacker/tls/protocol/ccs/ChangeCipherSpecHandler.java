/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.ccs;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ChangeCipherSpecHandler extends ProtocolMessageHandler<ChangeCipherSpecMessage> {

    public static final byte CCS_PROTOCOL_TYPE = 1;

    public ChangeCipherSpecHandler(TlsContext tlsContext) {
	super(tlsContext);
	correctProtocolMessageClass = ChangeCipherSpecMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	protocolMessage.setCcsProtocolType(CCS_PROTOCOL_TYPE);
	if ((tlsContext.isRenegotiation() && tlsContext.getMyConnectionEnd() == ConnectionEnd.CLIENT)
		|| tlsContext.getRecordHandler().getRecordCipher() == null) {
	    setRecordCipher();
	}
	byte[] result = { protocolMessage.getCcsProtocolType().getValue() };
	return result;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if ((tlsContext.isRenegotiation() && tlsContext.getMyConnectionEnd() == ConnectionEnd.SERVER)
		|| tlsContext.getRecordHandler().getRecordCipher() == null) {
	    setRecordCipher();
	}
	protocolMessage.setCcsProtocolType(message[pointer]);
	return pointer + 1;
    }

    public void setRecordCipher() {
	try {
	    TlsRecordBlockCipher tlsRecordBlockCipher = new TlsRecordBlockCipher(tlsContext);
	    tlsContext.getRecordHandler().setRecordCipher(tlsRecordBlockCipher);
	} catch (InvalidKeyException ex) {
	    throw new CryptoException(
		    "It was not possible to initialize an algorithm from "
			    + tlsContext.getSelectedCipherSuite()
			    + ". Most probably your platform does not support unlimited policy strength and you have to "
			    + "install Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files. Stupid, I know.",
		    ex);
	} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
	    throw new CryptoException(ex);
	}
    }
}
