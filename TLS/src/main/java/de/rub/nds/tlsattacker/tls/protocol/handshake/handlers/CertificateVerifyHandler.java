/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAndHashAlgorithm;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
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
	    // todo add support for algorithms beyond rsa
	    Key key = ks.getKey(tlsContext.getAlias(), tlsContext.getPassword().toCharArray());
	    RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key;

	    SignatureAndHashAlgorithm selectedSignatureHashAlgo = tlsContext
		    .getSupportedSignatureAndHashAlgorithmsForRSA().get(0);
	    LOGGER.debug("Selected SignatureAndHashAlgorithm for CertificateVerify message: {}",
		    selectedSignatureHashAlgo.getJavaName());
	    Signature instance = Signature.getInstance(selectedSignatureHashAlgo.getJavaName());
	    instance.initSign(privKey);
	    instance.update(rawHandshakeBytes);
	    byte[] signature = instance.sign();

	    protocolMessage.setSignature(signature);
	    protocolMessage.setSignatureLength(protocolMessage.getSignature().getValue().length);

	    byte[] result = ArrayConverter.concatenate(selectedSignatureHashAlgo.getValue(), ArrayConverter.intToBytes(
		    protocolMessage.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH),
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
	throw new UnsupportedOperationException("not supported yet");
    }

}
