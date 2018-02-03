package de.rub.nds.tlsattacker.core.protocol.handler;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.tls.Certificate;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.SSL2ServerVerifyParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ServerVerifyPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.CertificateUtils;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class SSL2ServerVerifyHandler extends HandshakeMessageHandler<SSL2ServerVerifyMessage> {

    public SSL2ServerVerifyHandler(TlsContext context) {
        super(context);
    }
	
	@Override
	public ProtocolMessageParser<SSL2ServerVerifyMessage> getParser(byte[] message, int pointer) {
		return new SSL2ServerVerifyParser(message, pointer, tlsContext.getChooser().getSelectedProtocolVersion());
	}

	@Override
	public ProtocolMessagePreparator<SSL2ServerVerifyMessage> getPreparator(SSL2ServerVerifyMessage message) {
		return new SSL2ServerVerifyPreparator(message, tlsContext.getChooser());
	}

	private byte[] MD5(byte[] input) {
		// TODO: Replace with BouncyCastle MD5
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
			return digest.digest(input);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
    @Override
    public void adjustTLSContext(SSL2ServerVerifyMessage message) {
    	byte[] md5Input = generateMD5Input();
    	byte[] md5Output = MD5(md5Input);
    	RC4Engine rc4 = new RC4Engine();
    	rc4.init(false, new KeyParameter(md5Output));
    	byte[] encrypted = message.getEncryptedPart().getValue();
    	int len = encrypted.length;
		byte[] decrypted = new byte[len];
    	rc4.processBytes(encrypted, 0, len, decrypted, 0);
    	LOGGER.debug("Decrypted Challenge: " + ArrayConverter.bytesToHexString(decrypted));
    	byte[] challenge = tlsContext.getClientRandom();
    	LOGGER.debug("Original Challenge: " + ArrayConverter.bytesToHexString(challenge));
    	byte[] test = Arrays.copyOfRange(decrypted, len - 16, len);
		if (Arrays.equals(test, challenge)) {
    		LOGGER.debug("Hurray! DROWN detected!");
    		// TODO: Where do we store this information? On the tlsContext?
    	}
    }

	private byte[] generateMD5Input() {
//    	MD5.new(CLEAR_KEY + cls.SECRET_KEY + '0' + CHALLENGE + connection_id).digest(
		// TODO: Use a proper method for copying between byte arrays.
		byte[] md5Input = new byte[16 * 3 + 1];

    	byte[] preMasterSecret = tlsContext.getPreMasterSecret();
    	for (int i = 0; i < 5; i++) {
			md5Input[11 + i] = preMasterSecret[i];
    	}
    	
    	md5Input[16] = '0';
    	
    	byte[] challenge = tlsContext.getClientRandom();
    	for (int i = 0; i < 16; i++) {
			md5Input[17 + i] = challenge[i];
    	}
    	
    	byte[] connectionId = tlsContext.getServerRandom();
    	for (int i = 0; i < 16; i++) {
    		md5Input[33 + i] = connectionId[i];
    	}
    	LOGGER.debug("MD5 Input: " + ArrayConverter.bytesToHexString(md5Input));
    	return md5Input;
	}

	@Override
	public ProtocolMessageSerializer getSerializer(SSL2ServerVerifyMessage message) {
		// TODO Auto-generated method stub
		return null;
	}
	
}
