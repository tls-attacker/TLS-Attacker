/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Arrays;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsDHUtils;
import org.bouncycastle.util.BigIntegers;
import sun.security.rsa.RSAKeyFactory;
import sun.security.rsa.RSAKeyPairGenerator;
import sun.security.rsa.RSAPrivateCrtKeyImpl;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */

public class DHEServerKeyExchangeHandler extends HandshakeMessageHandler<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(DHEServerKeyExchangeHandler.class);

    public DHEServerKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = DHEServerKeyExchangeMessage.class;
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
	nextPointer = currentPointer + HandshakeByteLength.DH_PARAM_LENGTH;
	int pLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setpLength(pLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + protocolMessage.getpLength().getValue();
	byte[] pBytes = Arrays.copyOfRange(message, currentPointer, nextPointer);
	protocolMessage.setSerializedP(pBytes);
	protocolMessage.setSerializedPLength(protocolMessage.getSerializedP().getValue().length);
	BigInteger p = new BigInteger(1, pBytes);
	protocolMessage.setP(p);

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.DH_PARAM_LENGTH;
	int gLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setgLength(gLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + protocolMessage.getgLength().getValue();
	byte[] gBytes = Arrays.copyOfRange(message, currentPointer, nextPointer);
	protocolMessage.setSerializedG(gBytes);
	protocolMessage.setSerializedGLength(protocolMessage.getSerializedG().getValue().length);
	BigInteger g = new BigInteger(1, gBytes);
	protocolMessage.setG(g);

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.DH_PARAM_LENGTH;
	int publicKeyLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setPublicKeyLength(publicKeyLength);

	currentPointer = nextPointer;
	nextPointer = currentPointer + protocolMessage.getPublicKeyLength().getValue();
	byte[] pkBytes = Arrays.copyOfRange(message, currentPointer, nextPointer);
	protocolMessage.setSerializedPublicKey(pkBytes);
	protocolMessage.setSerializedPublicKeyLength(protocolMessage.getSerializedPublicKey().getValue().length);
	BigInteger publicKey = new BigInteger(1, pkBytes);
	protocolMessage.setPublicKey(publicKey);

	byte[] dhParams = ArrayConverter
		.concatenate(ArrayConverter.intToBytes(protocolMessage.getpLength().getValue(),
			HandshakeByteLength.DH_PARAM_LENGTH), BigIntegers.asUnsignedByteArray(protocolMessage.getP()
			.getValue()), ArrayConverter.intToBytes(protocolMessage.getgLength().getValue(),
			HandshakeByteLength.DH_PARAM_LENGTH), BigIntegers.asUnsignedByteArray(protocolMessage.getG()
			.getValue()), ArrayConverter.intToBytes(protocolMessage.getPublicKeyLength().getValue(),
			HandshakeByteLength.DH_PARAM_LENGTH), BigIntegers.asUnsignedByteArray(protocolMessage
			.getPublicKey().getValue()));
	InputStream is = new ByteArrayInputStream(dhParams);

	try {
	    ServerDHParams publicKeyParameters = ServerDHParams.parse(is);

	    tlsContext.setServerDHParameters(publicKeyParameters);

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
	} catch (IOException ex) {
	    throw new WorkflowExecutionException("DH public key parsing failed", ex);
	}
    }

    @Override
    public byte[] prepareMessageAction() {
	// To use true DH ephemeral we need to precompute the prime number P(DH
	// modulus)
	/**
	 * int defaultPrimeProbability = 30;
	 * 
	 * DHParametersGenerator generator = new DHParametersGenerator();
	 * //Genration of a higher bit prime number takes too long (512 bits
	 * takes 2 seconds) generator.init(512, defaultPrimeProbability, new
	 * SecureRandom()); DHParameters params =
	 * generator.generateParameters();
	 */

	DHPublicKeyParameters dhPublic;

	// fixed DH modulus P and DH generator G
	byte[] pArray = ArrayConverter
		.hexStringToByteArray("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc"
			+ "74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d"
			+ "51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24"
			+ "117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83"
			+ "655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca1821"
			+ "7c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695"
			+ "5817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff");
	byte[] gArray = { 0x02 };
	BigInteger p = new BigInteger(1, pArray);
	BigInteger g = new BigInteger(1, gArray);
	DHParameters params = new DHParameters(p, g);

	KeyGenerationParameters kgp = new DHKeyGenerationParameters(new SecureRandom(), params);
	DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
	keyGen.init(kgp);
	AsymmetricCipherKeyPair serverKeyPair = keyGen.generateKeyPair();

	dhPublic = (DHPublicKeyParameters) serverKeyPair.getPublic();
	DHPrivateKeyParameters dhPrivate = (DHPrivateKeyParameters) serverKeyPair.getPrivate();

	protocolMessage.setG(dhPublic.getParameters().getG());
	protocolMessage.setP(dhPublic.getParameters().getP());
	protocolMessage.setPublicKey(dhPublic.getY());
	protocolMessage.setPrivateKey(dhPrivate.getX());
	tlsContext.setServerDHPrivateKeyParameters(dhPrivate);

	byte[] serializedP = BigIntegers.asUnsignedByteArray(protocolMessage.getP().getValue());
	protocolMessage.setSerializedP(serializedP);
	protocolMessage.setSerializedPLength(protocolMessage.getSerializedP().getValue().length);

	byte[] serializedG = BigIntegers.asUnsignedByteArray(protocolMessage.getG().getValue());
	protocolMessage.setSerializedG(serializedG);
	protocolMessage.setSerializedGLength(protocolMessage.getSerializedG().getValue().length);

	byte[] serializedPublicKey = BigIntegers.asUnsignedByteArray(protocolMessage.getPublicKey().getValue());
	protocolMessage.setSerializedPublicKey(serializedPublicKey);
	protocolMessage.setSerializedPublicKeyLength(protocolMessage.getSerializedPublicKey().getValue().length);

	byte[] dhParams = ArrayConverter.concatenate(ArrayConverter.intToBytes(protocolMessage.getSerializedPLength()
		.getValue(), HandshakeByteLength.DH_PARAM_LENGTH), protocolMessage.getSerializedP().getValue(),
		ArrayConverter.intToBytes(protocolMessage.getSerializedGLength().getValue(),
			HandshakeByteLength.DH_PARAM_LENGTH), protocolMessage.getSerializedG().getValue(),
		ArrayConverter.intToBytes(protocolMessage.getSerializedPublicKeyLength().getValue(),
			HandshakeByteLength.DH_PARAM_LENGTH), protocolMessage.getSerializedPublicKey().getValue());
	InputStream is = new ByteArrayInputStream(dhParams);

	try {
	    ServerDHParams publicKeyParameters = ServerDHParams.parse(is);

	    tlsContext.setServerDHParameters(publicKeyParameters);

	    KeyStore ks = tlsContext.getKeyStore();

	    // could be extended to choose the algorithms depending on the
	    // certificate
	    SignatureAndHashAlgorithm selectedSignatureHashAlgo = new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
		    HashAlgorithm.SHA1);
	    protocolMessage.setSignatureAlgorithm(selectedSignatureHashAlgo.getSignatureAlgorithm().getValue());
	    protocolMessage.setHashAlgorithm(selectedSignatureHashAlgo.getHashAlgorithm().getValue());

	    Key key = ks.getKey(tlsContext.getAlias(), tlsContext.getPassword().toCharArray());

	    RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;

	    Signature instance = Signature.getInstance(selectedSignatureHashAlgo.getJavaName());
	    instance.initSign(rsaKey);
	    LOGGER.debug("SignatureAndHashAlgorithm for ServerKeyExchange message: {}",
		    selectedSignatureHashAlgo.getJavaName());

	    byte[] toBeSignedBytes = ArrayConverter.concatenate(tlsContext.getClientRandom(),
		    tlsContext.getServerRandom(), dhParams);

	    instance.update(toBeSignedBytes);
	    byte[] signature = instance.sign();
	    protocolMessage.setSignature(signature);
	    protocolMessage.setSignatureLength(signature.length);

	    byte[] result = ArrayConverter.concatenate(dhParams,
		    new byte[] { protocolMessage.getHashAlgorithm().getValue(),
			    protocolMessage.getSignatureAlgorithm().getValue() }, ArrayConverter.intToBytes(
			    protocolMessage.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH),
		    protocolMessage.getSignature().getValue());

	    protocolMessage.setLength(result.length);

	    long header = (HandshakeMessageType.SERVER_KEY_EXCHANGE.getValue() << 24)
		    + protocolMessage.getLength().getValue();

	    protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		    ArrayConverter.longToUint32Bytes(header), result));

	} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException
		| SignatureException | IOException ex) {
	    throw new ConfigurationException(ex.getLocalizedMessage(), ex);
	}

	return protocolMessage.getCompleteResultingMessage().getValue();
    }
}
