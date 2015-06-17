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
package de.rub.nds.tlsattacker.tls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.FinishedMessage;
import de.rub.nds.tlsattacker.tls.record.handlers.RecordHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(FinishedHandler.class);

    public FinishedHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = FinishedMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	// protocolMessage.setType(HandshakeMessageType.FINISHED.getValue());

	byte[] masterSecret = tlsContext.getMasterSecret();

	byte[] handshakeMessagesHash = tlsContext.getDigest().digest();

	PRFAlgorithm prfAlgorithm = PRFAlgorithm.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		tlsContext.getSelectedCipherSuite());
	byte[] verifyData = PseudoRandomFunction.compute(tlsContext.getProtocolVersion(), masterSecret,
		PseudoRandomFunction.CLIENT_FINISHED_LABEL, handshakeMessagesHash, HandshakeByteLength.VERIFY_DATA,
		prfAlgorithm.getJavaName());

	protocolMessage.setVerifyData(verifyData);
	LOGGER.debug("Computed verify data: {}", ArrayConverter.bytesToHexString(verifyData));

	try {
	    if (RecordHandler.getInstance().getRecordCipher() == null) {
		TlsRecordBlockCipher tlsRecordBlockCipher = new TlsRecordBlockCipher(tlsContext);
		RecordHandler.getInstance().setRecordCipher(tlsRecordBlockCipher);
	    }

	    byte[] result = protocolMessage.getVerifyData().getValue();

	    protocolMessage.setLength(result.length);

	    long header = (protocolMessage.getHandshakeMessageType().getValue() << 24)
		    + protocolMessage.getLength().getValue();

	    protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		    ArrayConverter.longToUint32Bytes(header), result));

	    return protocolMessage.getCompleteResultingMessage().getValue();
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

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	FinishedMessage finishedMessage = (FinishedMessage) protocolMessage;
	if (message[pointer] != HandshakeMessageType.FINISHED.getValue()) {
	    throw new InvalidMessageTypeException("This is not a server finished message");
	}
	finishedMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	finishedMessage.setLength(length);

	currentPointer = nextPointer;
	nextPointer = currentPointer + length;
	byte[] verifyData = Arrays.copyOfRange(message, currentPointer, nextPointer);
	finishedMessage.setVerifyData(verifyData);

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	return nextPointer;
    }

}
