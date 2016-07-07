/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Handling of the CertificateVerify protocol message:
 * http://tools.ietf.org/html/rfc5246#section-7.4.8
 * 
 * The TLS spec as well as wireshark bring some nice confusions: - The TLS spec
 * says the message consists of only signature bytes - Wireshark says the
 * message consists of the signature length and signature bytes
 * 
 * In fact, the certificate message consists of the following fields: -
 * signature algorithm (2 bytes) - signature length (2 bytes) - signature
 * 
 * This structure is of course prepended with the handshake message length, as
 * obvious for every handshake message.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 * @param <HandshakeMessage>
 */
public class CertificateVerifyHandler<HandshakeMessage extends CertificateVerifyMessage> extends
	HandshakeMessageHandler<HandshakeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(CertificateVerifyHandler.class);

    public CertificateVerifyHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = CertificateVerifyMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {

	byte[] rawHandshakeBytes = tlsContext.getDigest().getRawBytes();
	// LOGGER.debug("All handshake messages: {}",
	// ArrayConverter.bytesToHexString(rawHandshakeBytes));

	KeyStore ks = tlsContext.getKeyStore();

	try {
	    String alias = tlsContext.getAlias();
	    String password = tlsContext.getPassword();
	    Key key = ks.getKey(alias, password.toCharArray());
	    Signature instance = null;
	    SignatureAndHashAlgorithm selectedSignatureHashAlgo = null;

	    switch (key.getAlgorithm()) {
		case "RSA":
		    RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
		    // TODO was ist wenn kein algorithm supported wird?
		    // TLS Context has no supportedSignatureHashAlgorithms
		    if (tlsContext.getSupportedSignatureAndHashAlgorithmsForRSA().size() == 0) {
			do {
			    // Choose one random
			    selectedSignatureHashAlgo = new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
				    generateRandomHashAlgorithm());
			    instance = Signature.getInstance(selectedSignatureHashAlgo.getJavaName());
			} while (instance == null);
			instance.initSign(rsaKey);
		    } else {
			selectedSignatureHashAlgo = tlsContext.getSupportedSignatureAndHashAlgorithmsForRSA().get(0);
			instance = Signature.getInstance(selectedSignatureHashAlgo.getJavaName());
			instance.initSign(rsaKey);
		    }

		    break;
		case "EC":
		    ECPrivateKey ecKey = (ECPrivateKey) key;
		    // TODO was ist wenn kein algorithm supported wird?
		    if (tlsContext.getSupportedSignatureAndHashAlgorithmsForEC().size() == 0) {
			// Choose one random
			do {
			    selectedSignatureHashAlgo = new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA,
				    generateRandomHashAlgorithm());
			    instance = Signature.getInstance(selectedSignatureHashAlgo.getJavaName());
			} while (instance == null);
			instance.initSign(ecKey);
		    } else {
			selectedSignatureHashAlgo = tlsContext.getSupportedSignatureAndHashAlgorithmsForEC().get(0);
			instance = Signature.getInstance(selectedSignatureHashAlgo.getJavaName());
			instance.initSign(ecKey);
		    }

		    break;
		default:
		    throw new ConfigurationException("Algorithm " + key.getAlgorithm() + " not supported yet.");
	    }

	    LOGGER.debug("Selected SignatureAndHashAlgorithm for CertificateVerify message: {}",
		    selectedSignatureHashAlgo.getJavaName());
	    instance.update(rawHandshakeBytes);
	    byte[] signature = instance.sign();

	    protocolMessage.setSignature(signature);
	    protocolMessage.setSignatureLength(protocolMessage.getSignature().getValue().length);

	    byte[] result = ArrayConverter.concatenate(selectedSignatureHashAlgo.getByteValue(), ArrayConverter
		    .intToBytes(protocolMessage.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH),
		    protocolMessage.getSignature().getValue());

	    protocolMessage.setLength(result.length);

	    long header = (protocolMessage.getHandshakeMessageType().getValue() << 24)
		    + protocolMessage.getLength().getValue();
	    protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		    ArrayConverter.longToUint32Bytes(header), result));

	    return protocolMessage.getCompleteResultingMessage().getValue();
	} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException
		| SignatureException ex) {
	    throw new ConfigurationException(ex.getLocalizedMessage(), ex);
	}
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.CERTIFICATE_VERIFY.getValue()) {
	    throw new InvalidMessageTypeException("This is not a Certificate Verify message");
	}
	protocolMessage.setType(message[pointer]);
	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;

	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);
	currentPointer = nextPointer;

	nextPointer = currentPointer + HandshakeByteLength.SIGNATURE_HASH_ALGORITHMS_LENGTH;
	SignatureAndHashAlgorithm sigAndHash = SignatureAndHashAlgorithm.getSignatureAndHashAlgorithm(Arrays
		.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setSignatureHashAlgorithm(sigAndHash.getByteValue());
	currentPointer = nextPointer;

	nextPointer = currentPointer + HandshakeByteLength.SIGNATURE_LENGTH;
	int sigLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setSignatureLength(sigLength);
	currentPointer = nextPointer;

	nextPointer = currentPointer + sigLength;
	protocolMessage.setSignature(Arrays.copyOfRange(message, currentPointer, nextPointer));
	currentPointer = nextPointer;
	// TODO maybe verify signature and set a boolean in TLS-Context

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	return currentPointer;
    }

    private HashAlgorithm generateRandomHashAlgorithm() {
	Random r = new Random();
	switch (r.nextInt(6)) {
	    case 0:
		return HashAlgorithm.MD5;
	    case 1:
		return HashAlgorithm.SHA1;
	    case 2:
		return HashAlgorithm.SHA224;
	    case 3:
		return HashAlgorithm.SHA256;
	    case 4:
		return HashAlgorithm.SHA384;
	    case 5:
		return HashAlgorithm.SHA512;

	}
	throw new RuntimeException("Could not generate HASH Algorithm");
    }

    private SignatureAlgorithm generateRandomSignatureAlgorithm() {
	Random r = new Random();
	switch (r.nextInt(4)) {
	    case 0:
		return SignatureAlgorithm.ANONYMOUS;

	    case 1:
		return SignatureAlgorithm.DSA;
	    case 2:
		return SignatureAlgorithm.ECDSA;
	    case 3:
		return SignatureAlgorithm.RSA;

	}
	throw new RuntimeException("Could not generate Signature Algorithm");
    }
}
