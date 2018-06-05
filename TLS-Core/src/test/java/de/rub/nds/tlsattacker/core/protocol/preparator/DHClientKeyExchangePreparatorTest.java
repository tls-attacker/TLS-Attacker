/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

public class DHClientKeyExchangePreparatorTest {

    private final static String DH_G = "a51883e9ac0539859df3d25c716437008bb4bd8ec4786eb4bc643299daef5e3e5af5863a6ac40a597b83a27583f6a658d408825105b16d31b6ed088fc623f648fd6d95e9cefcb0745763cddf564c87bcf4ba7928e74fd6a3080481f588d535e4c026b58a21e1e5ec412ff241b436043e29173f1dc6cb943c09742de989547288";
    private final static String DH_M = "da3a8085d372437805de95b88b675122f575df976610c6a844de99f1df82a06848bf7a42f18895c97402e81118e01a00d0855d51922f434c022350861d58ddf60d65bc6941fc6064b147071a4c30426d82fc90d888f94990267c64beef8c304a4b2b26fb93724d6a9472fa16bc50c5b9b8b59afb62cfe9ea3ba042c73a6ade35";
    private final static String RANDOM = "CAFEBABECAFE";
    private final static BigInteger SERVER_PUBLIC_KEY = new BigInteger(
            "49437715717798893754105488735114516682455843745607681454511055039168584592490468625265408270895845434581657576902999182876198939742286450124559319006108449708689975897919447736149482114339733412256412716053305356946744588719383899737036630001856916051516306568909530334115858523077759833807187583559767008031");
    private final static byte[] PREMASTERSECRET = ArrayConverter
            .hexStringToByteArray("3CDCE99BB99CCE256355C696A39E4B5BE3726FCC5F104EE36DD05CB68EA1102DAAEA515EB51F519E656EA8E2B4E2604CC9D4E017EE44B3854D133F5418688AC251D88196651611E5D91F5297B1C68989A208641F8C54AECBF4F360F2222FF692936F74803696E7627D7B2710A08CC21220042649277049ABA23FEA6422C3BE1C");
    private TlsContext context;
    private DHClientKeyExchangeMessage message;
    private DHClientKeyExchangePreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        context.getConfig().setDefaultServerDhGenerator(new BigInteger(DH_G, 16));
        context.getConfig().setDefaultServerDhModulus(new BigInteger(DH_M, 16));
        context.getConfig().setDefaultClientDhPrivateKey(
                new BigInteger("1234567891234567889123546712839632542648746452354265471"));
        message = new DHClientKeyExchangeMessage();
        preparator = new DHClientKeyExchangePreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * DHClientKeyExchangePreparator.
     */
    @Test
    public void testPrepare() {
        // prepare context
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256);
        context.setClientRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        context.setServerRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        // set server DH-parameters
        context.setServerDhModulus(new BigInteger(DH_M, 16));
        context.setServerDhGenerator(new BigInteger(DH_G, 16));
        context.setServerDhPublicKey(SERVER_PUBLIC_KEY);

        preparator.prepareHandshakeMessageContents();

        // Tests
        assertArrayEquals(PREMASTERSECRET, message.getComputations().getPremasterSecret().getValue());
        assertNotNull(message.getPublicKeyLength().getValue());
        assertNotNull(message.getPublicKey());
        assertNotNull(message.getComputations().getClientServerRandom());
        assertArrayEquals(
                ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray(RANDOM),
                        ArrayConverter.hexStringToByteArray(RANDOM)), message.getComputations().getClientServerRandom()
                        .getValue());

    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }

    @Test
    public void testPrepareAfterParse() {
        // This method should only be called when we received the message before
        message.setPublicKey(context.getChooser().getDhClientPublicKey().toByteArray());
        preparator.prepareAfterParse(false);
    }

    @Test
    public void testPrepareAfterParseReverseMode() {
        preparator.prepareAfterParse(true);
    }
}
