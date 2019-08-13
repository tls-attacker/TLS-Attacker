package de.rub.nds.tlsattacker.core.protocol.serializer;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;

@RunWith(Parameterized.class)
public class SSL2ClientMasterKeySerializerTest {

	final private ProtocolVersion VERSION  = ProtocolVersion.SSL2;
	private SSL2ClientMasterKeyMessage message;
	private byte[] expectedClientMasterKeyMessage;
	
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
		byte[] expectedClientMasterKeyMessage = ArrayConverter.hexStringToByteArray(
		 "808a02010080000000800000b28367d5b44f6f585096540ab798705ecb6ce66336d5068952db71542701870754fdc25da8414d0977ec0401b5ff4cc853779d6069be867bf65a2250d14a189d74c608f4f76a9aa8a4f1a909370b86f5fd0740d368083e78e1034e38573b32799cf59ea52a771633ffdbd0e8123ada764f677cd09b05106ea9af8168a71249d4"
		);		
		byte[]  encryptedKey = ArrayConverter.hexStringToByteArray(
		 "b28367d5b44f6f585096540ab798705ecb6ce66336d5068952db71542701870754fdc25da8414d0977ec0401b5ff4cc853779d6069be867bf65a2250d14a189d74c608f4f76a9aa8a4f1a909370b86f5fd0740d368083e78e1034e38573b32799cf59ea52a771633ffdbd0e8123ada764f677cd09b05106ea9af8168a71249d4"
		);
    	byte[] cipher = BigInteger.valueOf(SSL2CipherSuite.SSL_CK_RC4_128_WITH_MD5.getValue()).toByteArray();
        
    	return Arrays.asList(new Object[][] {{
    		138,													// Length : 138
    		HandshakeMessageType.SSL2_CLIENT_MASTER_KEY.getValue(),	// Type: Client Master Key (2)
    		cipher, 												// Cipher Spec : SSL2_RC4_128_WITH_MD5 (0x010080)
    		0,	 													// Clear Key Data Length : 0
    		128,													// Encrypted Key Data Length: 128
    		0,														// Key Argument Length: 0
    		new byte[0],  											// Clear Key: -
    		encryptedKey,											// Encrypted Key
    		expectedClientMasterKeyMessage
        }});   	
    }
    
    public SSL2ClientMasterKeySerializerTest(int messageLength, byte messageType, byte[] cipher, int clearKeyLength,
    		int encryptedKeyLength, int keyArgLength, byte[] clearKeyData,byte[] encryptedKey, byte[] expectedClientMasterKeyMessage) {    	
    	this.expectedClientMasterKeyMessage = expectedClientMasterKeyMessage;
    	this.message = new SSL2ClientMasterKeyMessage();
		this.message.setMessageLength(138);
		this.message.setType(messageType);
		this.message.setCipherKind(cipher);
		this.message.setClearKeyLength(clearKeyLength);
		this.message.setEncryptedKeyLength(encryptedKeyLength);	
		this.message.setKeyArgLength(keyArgLength);
		this.message.setClearKeyData(clearKeyData);
		this.message.setEncryptedKeyData(encryptedKey);   	
    }
    
	@Test
	public void test() {
		SSL2ClientMasterKeySerializer serializer = new SSL2ClientMasterKeySerializer(this.message, this.VERSION);
		byte[] result = serializer.serializeProtocolMessageContent();			
		assertArrayEquals(this.expectedClientMasterKeyMessage,result);
	}
}
