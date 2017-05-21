/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler.extension;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KSEntry;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.extension.KeyShareExtensionParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.extension.KeyShareExtensionPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.KeyShareExtensionSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
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
        context.getConfig().setConnectionEnd(ConnectionEnd.SERVER);
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
        context.setServerKSEntry(new KSEntry(NamedCurve.FFDHE2048, ArrayConverter.hexStringToByteArray("0800000000000000000000")));
        context.getConfig().setConnectionEnd(ConnectionEnd.SERVER);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        handler = new KeyShareExtensionHandler(context);
        byte[] sharedSecret = handler.computeSharedSecretDH();
        int sharedSecretLength = sharedSecret.length;
        int sharedSecretLength_correct = context.getConfig().getFixedDHModulus().length;
        byte[] sharedSecret_correct = ArrayConverter.bigIntegerToNullPaddedByteArray(new BigInteger(1,
                ArrayConverter.hexStringToByteArray("05BD8BC42DC32129EDF82693CC41D91FB6BD07E917BE13AA4D5FF2BF2EE8C25FCC52F8F344E5B715570FECCBA4693AAE9615B46FA13DA4E8A1593B220D134687EE955A7534D0EA15093ADDD04C396CF87A6F3A7589D289B7609FC18B98BF6445105BF3E69C0E01DC652374EEEAB2C4400B6166255176F7E13550890DE85B59ABD8732A362B6BD0B2FFC10882AE8C578401A092E3A711BEA2FDB4ECA7529ABC40C60AF5B208F8001F6E9DEFACB8C50CBF8E0D20F9B802EA25BFC642483905E8DA2AA3788D28C1190AB4B2C261E2EB99B73BCFB867DAE6F4CE3D23EC5F72A8DBAE37980DB1D8ABF7C01C05C9EBE4D8F07A128DB2428E69BFF36D070A52A107565D")),
                sharedSecretLength_correct);
        assertTrue(sharedSecretLength == sharedSecretLength_correct);
        assertArrayEquals(sharedSecret, sharedSecret_correct);
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
