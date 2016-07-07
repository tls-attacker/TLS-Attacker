/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.math.ec.ECPoint;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHEServerKeyExchangeHandler extends HandshakeMessageHandler<ECDHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(ECDHEServerKeyExchangeHandler.class);

    public ECDHEServerKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ECDHEServerKeyExchangeMessage.class;
    }

    /**
     * @param message
     * @param pointer
     * @return
     */
    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue()) {
	    throw new InvalidMessageTypeException(HandshakeMessageType.SERVER_KEY_EXCHANGE);
	}
	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);

	currentPointer = nextPointer;
	nextPointer++;
	EllipticCurveType ct = EllipticCurveType.getCurveType(message[currentPointer]);
	if (ct != EllipticCurveType.NAMED_CURVE) {
	    throw new UnsupportedOperationException("Currently only named curves are supported");
	}
	protocolMessage.setCurveType(ct.getValue());

	currentPointer = nextPointer;
	nextPointer = currentPointer + NamedCurve.LENGTH;
	NamedCurve nc = NamedCurve.getNamedCurve(Arrays.copyOfRange(message, currentPointer, nextPointer));
	// TODO ....
	if (nc == null) {
	    LOGGER.log(Level.INFO, "Named Curve: null");
	    nc = NamedCurve.SECT163R1;
	}
	protocolMessage.setNamedCurve(nc.getValue());

	currentPointer = nextPointer;
	nextPointer++;
	int publicKeyLength = message[currentPointer] & 0xFF;
	protocolMessage.setPublicKeyLength(publicKeyLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + publicKeyLength;
	protocolMessage.setPublicKey(Arrays.copyOfRange(message, currentPointer, nextPointer));

	byte[] ecParams = ArrayConverter.concatenate(new byte[] { protocolMessage.getCurveType().getValue() },
		protocolMessage.getNamedCurve().getValue(), ArrayConverter.intToBytes(protocolMessage
			.getPublicKeyLength().getValue(), 1), protocolMessage.getPublicKey().getValue());
	InputStream is = new ByteArrayInputStream(ecParams);
	ECPublicKeyParameters publicKeyParameters = null;
	try {
	    publicKeyParameters = ECCUtilsBCWrapper.readECParametersWithPublicKey(is);
	    LOGGER.debug("Parsed the following EC domain parameters: ");
	    LOGGER.debug("  Curve order: {}", publicKeyParameters.getParameters().getCurve().getOrder());
	    LOGGER.debug("  Parameter A: {}", publicKeyParameters.getParameters().getCurve().getA());
	    LOGGER.debug("  Parameter B: {}", publicKeyParameters.getParameters().getCurve().getB());
	    LOGGER.debug("  Base point: {} ", publicKeyParameters.getParameters().getG());
	    LOGGER.debug("  Public key point Q: {} ", publicKeyParameters.getQ());
	} catch (TlsFatalAlert alert) {
	    throw new UnsupportedOperationException("Problematic EC parameters, we dont support these yet");
	} catch (IOException ex) {
	    throw new WorkflowExecutionException("EC public key parsing failed", ex);
	}
	tlsContext.getEcContext().setServerPublicKeyParameters(publicKeyParameters);

	if (tlsContext.getProtocolVersion() == ProtocolVersion.DTLS12
		|| tlsContext.getProtocolVersion() == ProtocolVersion.TLS12) {
	    currentPointer = nextPointer;
	    nextPointer++;
	    HashAlgorithm ha = HashAlgorithm.getHashAlgorithm(message[currentPointer]);
	    protocolMessage.setHashAlgorithm(ha.getValue());

	    currentPointer = nextPointer;
	    nextPointer++;
	    SignatureAlgorithm sa = SignatureAlgorithm.getSignatureAlgorithm(message[currentPointer]);
	    protocolMessage.setSignatureAlgorithm(sa.getValue());
	}
	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.SIGNATURE_LENGTH;
	int signatureLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setSignatureLength(signatureLength);
	currentPointer = nextPointer;
	nextPointer = currentPointer + signatureLength;
	protocolMessage.setSignature(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));
	return nextPointer;

    }

    @Override
    public byte[] prepareMessageAction() {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
