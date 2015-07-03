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

import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messagefields.HandshakeMessageFields;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateVerifyMessage;
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
	    Key key = ks.getKey(tlsContext.getAlias(), tlsContext.getPassword().toCharArray());
	    Signature instance = null;
	    SignatureAndHashAlgorithm selectedSignatureHashAlgo = null;
	    switch (key.getAlgorithm()) {
		case "RSA":
		    RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
		    selectedSignatureHashAlgo = tlsContext.getSupportedSignatureAndHashAlgorithmsForRSA().get(0);
		    instance = Signature.getInstance(selectedSignatureHashAlgo.getJavaName());
		    instance.initSign(rsaKey);
		    break;
		case "EC":
		    ECPrivateKey ecKey = (ECPrivateKey) key;
		    selectedSignatureHashAlgo = tlsContext.getSupportedSignatureAndHashAlgorithmsForEC().get(0);
		    instance = Signature.getInstance(selectedSignatureHashAlgo.getJavaName());
		    instance.initSign(ecKey);
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

	    byte[] result = ArrayConverter.concatenate(selectedSignatureHashAlgo.getValue(), ArrayConverter.intToBytes(
		    protocolMessage.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH),
		    protocolMessage.getSignature().getValue());

	    HandshakeMessageFields protocolMessageFields = (HandshakeMessageFields) protocolMessage.getMessageFields();
	    protocolMessageFields.setLength(result.length);

	    long header = (protocolMessage.getHandshakeMessageType().getValue() << 24)
		    + protocolMessageFields.getLength().getValue();
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
	throw new UnsupportedOperationException("not supported yet");
    }

}
