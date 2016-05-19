/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class FinishedHandler extends HandshakeMessageHandler<FinishedMessage> {

    private static final Logger LOGGER = LogManager.getLogger(FinishedHandler.class);

    public FinishedHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = FinishedMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	// protocolMessage.setType(HandshakeMessageType.FINISHED.getValue());

	byte[] masterSecret = tlsContext.getMasterSecret();

	byte[] handshakeMessagesHash = tlsContext.getDigest().digest();

	PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		tlsContext.getSelectedCipherSuite());

	byte[] verifyData;

	if (tlsContext.getMyConnectionEnd() == ConnectionEnd.SERVER) {
	    verifyData = PseudoRandomFunction.compute(prfAlgorithm, masterSecret,
		    PseudoRandomFunction.SERVER_FINISHED_LABEL, handshakeMessagesHash, HandshakeByteLength.VERIFY_DATA);
	} else {
	    verifyData = PseudoRandomFunction.compute(prfAlgorithm, masterSecret,
		    PseudoRandomFunction.CLIENT_FINISHED_LABEL, handshakeMessagesHash, HandshakeByteLength.VERIFY_DATA);
	}
	protocolMessage.setVerifyData(verifyData);
	LOGGER.debug("Computed verify data: {}", ArrayConverter.bytesToHexString(verifyData));

	byte[] result = protocolMessage.getVerifyData().getValue();

	protocolMessage.setLength(result.length);

	long header = (protocolMessage.getHandshakeMessageType().getValue() << 24)
		+ protocolMessage.getLength().getValue();

	protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		ArrayConverter.longToUint32Bytes(header), result));

	return protocolMessage.getCompleteResultingMessage().getValue();
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
