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
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.math.BigInteger;
import java.util.Random;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Malena Ebert - malena-rub@ebert.li
 */
public class DHClientKeyExchangePreparatorTest {

    private final static String DH_G = "a51883e9ac0539859df3d25c716437008bb4bd8ec4786eb4bc643299daef5e3e5af5863a6ac40a597b83a27583f6a658d408825105b16d31b6ed088fc623f648fd6d95e9cefcb0745763cddf564c87bcf4ba7928e74fd6a3080481f588d535e4c026b58a21e1e5ec412ff241b436043e29173f1dc6cb943c09742de989547288";
    private final static String DH_M = "da3a8085d372437805de95b88b675122f575df976610c6a844de99f1df82a06848bf7a42f18895c97402e81118e01a00d0855d51922f434c022350861d58ddf60d65bc6941fc6064b147071a4c30426d82fc90d888f94990267c64beef8c304a4b2b26fb93724d6a9472fa16bc50c5b9b8b59afb62cfe9ea3ba042c73a6ade35";
    private final static String RANDOM = "CAFEBABECAFE";
    private final static BigInteger SERVER_PUBLIC_KEY = new BigInteger(
            "49437715717798893754105488735114516682455843745607681454511055039168584592490468625265408270895845434581657576902999182876198939742286450124559319006108449708689975897919447736149482114339733412256412716053305356946744588719383899737036630001856916051516306568909530334115858523077759833807187583559767008031");
    private final static byte[] PREMASTERSECRET = ArrayConverter
            .hexStringToByteArray("28ecc3fc89b1975d2e6568a04b059645bf5c618d18084993c43309cf8059ec6c9c306ef7440fb796671c695932fda39c8af073bd6540ba1f38fdc8d492b92babb9f0997e46115215a80fc74581aa2f9d74f1cb545989310af303a01ca62cd2207cd3ebdeb282c6dfedbed5390cbacfb4cf3ce330f044b260180740e973dfb347");
    private final static byte[] MASTERSECRET = ArrayConverter
            .hexStringToByteArray("7d21f8106301d895e43892f12bccb709d93939886b1d8f29b71bb8879aa55d19db0fc63fedb2fda91f6c544b09d88713");
    private TlsContext context;
    private DHClientKeyExchangeMessage message;
    private DHClientKeyExchangePreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new DHClientKeyExchangeMessage();
        preparator = new DHClientKeyExchangePreparator(context, message);
        RandomHelper.setRandom(new Random(0));
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
        context.setServerDHParameters(new ServerDHParams(new DHPublicKeyParameters(SERVER_PUBLIC_KEY, new DHParameters(
                new BigInteger(DH_M, 16), new BigInteger(DH_G, 16)))));

        preparator.prepareHandshakeMessageContents();

        // Tests
        assertArrayEquals(ArrayConverter.hexStringToByteArray(DH_G), message.getG().getByteArray());
        assertArrayEquals(ArrayConverter.hexStringToByteArray(DH_M), message.getP().getByteArray());
        assertArrayEquals(PREMASTERSECRET, message.getComputations().getPremasterSecret().getValue());
        assertArrayEquals(MASTERSECRET, message.getComputations().getMasterSecret().getValue());
        assertNotNull(message.getSerializedPublicKeyLength().getValue());
        assertNotNull(message.getSerializedPublicKey());
        assertNotNull(message.getComputations().getClientRandom());
        assertArrayEquals(
                ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray(RANDOM),
                        ArrayConverter.hexStringToByteArray(RANDOM)), message.getComputations().getClientRandom()
                        .getValue());

    }
}
