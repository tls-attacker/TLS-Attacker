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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class DHEServerKeyExchangePreparatorTest {

    private TlsContext context;
    private DHEServerKeyExchangePreparator preparator;
    private DHEServerKeyExchangeMessage message;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new DHEServerKeyExchangeMessage();
        preparator = new DHEServerKeyExchangePreparator(context.getChooser(), message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * DHEServerKeyExchangePreparator.
     */
    @Test
    public void testPrepare() {
        context.getConfig()
                .setDefaultServerDhGenerator(
                        new BigInteger(
                                ArrayConverter
                                        .hexStringToByteArray("a51883e9ac0539859df3d25c716437008bb4bd8ec4786eb4bc643299daef5e3e5af5863a6ac40a597b83a27583f6a658d408825105b16d31b6ed088fc623f648fd6d95e9cefcb0745763cddf564c87bcf4ba7928e74fd6a3080481f588d535e4c026b58a21e1e5ec412ff241b436043e29173f1dc6cb943c09742de989547288")));
        context.getConfig()
                .setDefaultServerDhModulus(
                        new BigInteger(
                                1,
                                ArrayConverter
                                        .hexStringToByteArray("da3a8085d372437805de95b88b675122f575df976610c6a844de99f1df82a06848bf7a42f18895c97402e81118e01a00d0855d51922f434c022350861d58ddf60d65bc6941fc6064b147071a4c30426d82fc90d888f94990267c64beef8c304a4b2b26fb93724d6a9472fa16bc50c5b9b8b59afb62cfe9ea3ba042c73a6ade35")));
        context.setClientRandom(ArrayConverter.hexStringToByteArray("AABBCCDD"));
        context.setServerRandom(ArrayConverter.hexStringToByteArray("AABBCCDD"));
        // Set Signature and Hash Algorithm
        List<SignatureAndHashAlgorithm> SigAndHashList = new LinkedList<>();
        SigAndHashList.add(SignatureAndHashAlgorithm.RSA_SHA1);
        SigAndHashList.add(SignatureAndHashAlgorithm.DSA_MD5);
        context.getConfig().setDefaultClientSupportedSignatureAndHashAlgorithms(SigAndHashList);
        // Test
        preparator.prepareHandshakeMessageContents();

        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("a51883e9ac0539859df3d25c716437008bb4bd8ec4786eb4bc643299daef5e3e5af5863a6ac40a597b83a27583f6a658d408825105b16d31b6ed088fc623f648fd6d95e9cefcb0745763cddf564c87bcf4ba7928e74fd6a3080481f588d535e4c026b58a21e1e5ec412ff241b436043e29173f1dc6cb943c09742de989547288"),
                message.getGenerator().getValue());
        assertArrayEquals(
                ArrayConverter
                        .hexStringToByteArray("da3a8085d372437805de95b88b675122f575df976610c6a844de99f1df82a06848bf7a42f18895c97402e81118e01a00d0855d51922f434c022350861d58ddf60d65bc6941fc6064b147071a4c30426d82fc90d888f94990267c64beef8c304a4b2b26fb93724d6a9472fa16bc50c5b9b8b59afb62cfe9ea3ba042c73a6ade35"),
                message.getModulus().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("AABBCCDDAABBCCDD"), message.getComputations()
                .getClientServerRandom().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0201"), message.getSignatureAndHashAlgorithm()
                .getValue());
        assertNotNull(message.getSignature().getValue());
        assertNotNull(message.getSignatureLength().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
