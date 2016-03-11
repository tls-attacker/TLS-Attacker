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
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class RSAClientKeyExchangeHandler extends ClientKeyExchangeHandler<RSAClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(RSAClientKeyExchangeHandler.class);

    public RSAClientKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = RSAClientKeyExchangeMessage.class;
	this.keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA;
    }

    @Override
    byte[] prepareKeyExchangeMessage() {
	RSAPublicKey publicKey = (RSAPublicKey) tlsContext.getX509ServerCertificateObject().getPublicKey();

	int keyByteLength = publicKey.getModulus().bitLength() / 8;

	// the number of random bytes in the pkcs1 message
	int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 3;
	byte[] padding = new byte[randomByteLength];
	RandomHelper.getRandom().nextBytes(padding);
	ArrayConverter.makeArrayNonZero(padding);

	byte[] premasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
	if (tlsContext.isTHSAttack()) {
	    premasterSecret = tlsContext.getPreMasterSecret();
	}else if (tlsContext.isMitMAttack()){
            premasterSecret = protocolMessage.getPremasterSecret().getValue();
        } 
        else {
	    RandomHelper.getRandom().nextBytes(premasterSecret);
	    premasterSecret[0] = tlsContext.getProtocolVersion().getMajor();
	    premasterSecret[1] = tlsContext.getProtocolVersion().getMinor();
	}

	protocolMessage.setPremasterSecret(premasterSecret);
	LOGGER.debug("Computed PreMaster Secret: {}",
		ArrayConverter.bytesToHexString(protocolMessage.getPremasterSecret().getValue()));

	protocolMessage.setPlainPaddedPremasterSecret(ArrayConverter.concatenate(new byte[] { 0x00, 0x02 }, padding,
		new byte[] { 0x00 }, protocolMessage.getPremasterSecret().getValue()));

	byte[] paddedPremasterSecret = protocolMessage.getPlainPaddedPremasterSecret().getValue();

	byte[] random = tlsContext.getClientServerRandom();

	PRFAlgorithm prfAlgorithm = PRFAlgorithm.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		tlsContext.getSelectedCipherSuite());
	byte[] masterSecret = PseudoRandomFunction.compute(tlsContext.getProtocolVersion(), protocolMessage
		.getPremasterSecret().getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random,
		HandshakeByteLength.MASTER_SECRET, prfAlgorithm.getJavaName());
	protocolMessage.setMasterSecret(masterSecret);
	LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

	tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

	try {
	    Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
	    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	    LOGGER.debug("Encrypting the following padded premaster secret: {}",
		    ArrayConverter.bytesToHexString(paddedPremasterSecret));
	    byte[] encrypted = cipher.doFinal(paddedPremasterSecret);
	    protocolMessage.setEncryptedPremasterSecret(encrypted);
	    protocolMessage
		    .setEncryptedPremasterSecretLength(protocolMessage.getEncryptedPremasterSecret().getValue().length);
	    return ArrayConverter.concatenate(ArrayConverter.intToBytes(protocolMessage
		    .getEncryptedPremasterSecretLength().getValue(),
		    HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH), protocolMessage
		    .getEncryptedPremasterSecret().getValue());
	} catch (BadPaddingException | IllegalBlockSizeException | NoSuchProviderException | InvalidKeyException
		| NoSuchAlgorithmException | NoSuchPaddingException ex) {
	    LOGGER.info(ex);
	    throw new WorkflowExecutionException(ex.getLocalizedMessage());
	}

    }

    @Override
    int parseKeyExchangeMessage(byte[] message, int currentPointer) {
	int nextPointer = currentPointer + HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setEncryptedPremasterSecretLength(length);
	currentPointer = nextPointer;

	nextPointer = currentPointer + length;
	protocolMessage.setEncryptedPremasterSecret(Arrays.copyOfRange(message, currentPointer, nextPointer));

	byte[] encryptedPremasterSecret = protocolMessage.getEncryptedPremasterSecret().getValue();

	KeyStore ks = tlsContext.getKeyStore();

	try {
	    Key key = ks.getKey(tlsContext.getAlias(), tlsContext.getPassword().toCharArray());
	    RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;

	    Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
	    cipher.init(Cipher.DECRYPT_MODE, rsaKey);
	    LOGGER.debug("Decrypting the following encrypted premaster secret: {}",
		    ArrayConverter.bytesToHexString(encryptedPremasterSecret));
	    byte[] decrypted = cipher.doFinal(encryptedPremasterSecret);

	    protocolMessage.setPlainPaddedPremasterSecret(decrypted);

	} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException
		| NoSuchProviderException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
	    throw new ConfigurationException(
		    "Something went wrong loading key from Keystore or decrypting Premastersecret", ex);
	}

	byte[] plainPaddedPremasterSecret = protocolMessage.getPlainPaddedPremasterSecret().getValue();

	int plainPaddedPremasterSecretLength = plainPaddedPremasterSecret.length;

	int plainPaddedPremasterSecretoffset = plainPaddedPremasterSecretLength - 48;

	byte[] premasterSecret = Arrays.copyOfRange(plainPaddedPremasterSecret, plainPaddedPremasterSecretoffset,
		plainPaddedPremasterSecretLength);

	LOGGER.debug("Resulting premaster secret: {}", ArrayConverter.bytesToHexString(premasterSecret));

	protocolMessage.setPremasterSecret(premasterSecret);
	tlsContext.setPreMasterSecret(premasterSecret);

	byte[] random = tlsContext.getClientServerRandom();

	PRFAlgorithm prfAlgorithm = PRFAlgorithm.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		tlsContext.getSelectedCipherSuite());
	byte[] masterSecret = PseudoRandomFunction.compute(tlsContext.getProtocolVersion(), protocolMessage
		.getPremasterSecret().getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random,
		HandshakeByteLength.MASTER_SECRET, prfAlgorithm.getJavaName());
	protocolMessage.setMasterSecret(masterSecret);
	LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

	tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

	currentPointer = nextPointer;

	return currentPointer;
    }
}
