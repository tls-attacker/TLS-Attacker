/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Nurullah Erinola
 */
public class KeyShareExtensionHandlerTest {

    private TlsContext context;
    private KeyShareExtensionHandler handler;

    public KeyShareExtensionHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new KeyShareExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        context.setTalkingConnectionEnd(ConnectionEnd.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        KeyShareExtensionMessage msg = new KeyShareExtensionMessage();
        List<KeySharePair> pairList = new LinkedList<>();
        KeySharePair pair = new KeySharePair();
        pair.setKeyShare(ArrayConverter.hexStringToByteArray("11"));
        pair.setKeyShareType(NamedCurve.FFDHE2048.getValue());
        pairList.add(pair);
        msg.setKeyShareList(pairList);
        handler.adjustTLSContext(msg);
        assertNotNull(context.getServerKSEntry());
        KSEntry entry = context.getServerKSEntry();
        assertArrayEquals(ArrayConverter.hexStringToByteArray("11"), entry.getSerializedPublicKey());
        assertTrue(entry.getGroup() == NamedCurve.FFDHE2048);
        assertNotNull(context.getClientHandshakeTrafficSecret());
        assertNotNull(context.getServerHandshakeTrafficSecret());

    }

    /**
     * Test of computeSharedSecretDH method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testComputeSharedSecretDH() {
        context.setServerKSEntry(new KSEntry(NamedCurve.FFDHE2048, ArrayConverter
                .hexStringToByteArray("0800000000000000000000")));
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        handler = new KeyShareExtensionHandler(context);
        byte[] sharedSecret = handler.computeSharedSecretDH();
        int sharedSecretLength = sharedSecret.length;
        int sharedSecretLength_correct = context.getConfig().getFixedDHModulus().length;
        byte[] sharedSecret_correct = ArrayConverter.bigIntegerToNullPaddedByteArray(new BigInteger(1, ArrayConverter
                .hexStringToByteArray("05BD8BC42DC32129EDF82693CC41D91FB6BD07E917BE13AA4D5FF2BF2EE8C25FCC52F8F344E5B715570FECCBA4693AAE9615B46FA13DA4E8A1593B220D134687EE955A7534D0EA15093ADDD04C396CF87A6F3A7589D289B7609FC18B98BF6445105BF3E69C0E01DC652374EEEAB2C4400B6166255176F7E13550890DE85B59ABD8732A362B6BD0B2FFC10882AE8C578401A092E3A711BEA2FDB4ECA7529ABC40C60AF5B208F8001F6E9DEFACB8C50CBF8E0D20F9B802EA25BFC642483905E8DA2AA3788D28C1190AB4B2C261E2EB99B73BCFB867DAE6F4CE3D23EC5F72A8DBAE37980DB1D8ABF7C01C05C9EBE4D8F07A128DB2428E69BFF36D070A52A107565D")),
                sharedSecretLength_correct);
        assertTrue(sharedSecretLength == sharedSecretLength_correct);
        assertArrayEquals(sharedSecret, sharedSecret_correct);
    }

    /**
     * Test of computeSharedSecretDH method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testComputeSharedSecretECDH() {
        context.setServerKSEntry(new KSEntry(NamedCurve.ECDH_X25519, ArrayConverter
                .hexStringToByteArray("9c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c")));
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        handler = new KeyShareExtensionHandler(context);
        byte[] sharedSecret = handler.computeSharedSecretECDH();
        byte[] sharedSecret_correct = ArrayConverter.hexStringToByteArray("0dfa4c5e11a6f606d4b75f138412d85a4b2da0d5f981ffc1d2e8ceff2e00a12c");
        assertArrayEquals(sharedSecret, sharedSecret_correct);
    }
    
    /**
     * Test of doECDH method, of class KeyShareExtensionHandler with keys from KeyPairGenerator.
     */
    @Test
    public void testECDH() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("curve25519");
        ECParameterSpec parameters = new ECParameterSpec(params.getCurve(), params.getG(), params.getH(), params.getH(), params.getSeed());
        kpgen.initialize(parameters, new SecureRandom());
        KeyPair pairA = kpgen.generateKeyPair();
        KeyPair pairB = kpgen.generateKeyPair();
        
        byte[] dataPrvA = handler.savePrivateKey(pairA.getPrivate());
        byte[] dataPubA = handler.savePublicKey(pairA.getPublic());
        byte[] dataPrvB = handler.savePrivateKey(pairB.getPrivate());
        byte[] dataPubB = handler.savePublicKey(pairB.getPublic());
        
        System.out.println("Alice Prv: " + ArrayConverter.bytesToHexString(dataPrvA));
        System.out.println("Alice Pub: " + ArrayConverter.bytesToHexString(dataPubA));
        System.out.println("Bob Prv: " + ArrayConverter.bytesToHexString(dataPrvB));
        System.out.println("Bob Pub: " + ArrayConverter.bytesToHexString(dataPubB));
        
        handler = new KeyShareExtensionHandler(context);
        System.out.println("Aus A Sicht:" + ArrayConverter.bytesToHexString(handler.doECDH(dataPrvA, dataPubB)));
        System.out.println("Aus B Sicht: " + ArrayConverter.bytesToHexString(handler.doECDH(dataPrvB, dataPubA)));
        assertArrayEquals(handler.doECDH(dataPrvA, dataPubB), handler.doECDH(dataPrvB, dataPubA));
    }

    /**
     * Test of getParser method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0, 2, 3, }, 0) instanceof KeyShareExtensionParser);
    }

    /**
     * Test of getPreparator method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new KeyShareExtensionMessage()) instanceof KeyShareExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class KeyShareExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new KeyShareExtensionMessage()) instanceof KeyShareExtensionSerializer);
    }
}
