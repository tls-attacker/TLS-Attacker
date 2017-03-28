/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangePreparatorTest {

    private TlsContext context;
    private DHEServerKeyExchangePreparator preparator;
    private DHEServerKeyExchangeMessage message;

    public DHEServerKeyExchangePreparatorTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new DHEServerKeyExchangeMessage();
        preparator = new DHEServerKeyExchangePreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * DHEServerKeyExchangePreparator.
     */
    @Test
    public void testPrepare() {
        // TODO
        context.getConfig().setFixedDHg(ArrayConverter.hexStringToByteArray("AABBCCDDEE"));
        context.getConfig().setFixedDHModulus(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        context.setClientRandom(ArrayConverter.hexStringToByteArray("AABBCCDD"));
        context.setServerRandom(ArrayConverter.hexStringToByteArray("AABBCCDD"));
        // Set Signature and Hash Algorithm
        List<SignatureAndHashAlgorithm> SigAndHashList = new LinkedList<>();
        SigAndHashList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1));
        SigAndHashList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.DSA, HashAlgorithm.MD5));
        context.getConfig().setSupportedSignatureAndHashAlgorithms(SigAndHashList);
        // Generate RSA key pair
        KeyPairGenerator keyGen = null;
        try {
        	keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new PreparationException("Could not generate a new Key", ex);
        }
        context.getConfig().setPrivateKey(keyGen.genKeyPair().getPrivate());
        // Test
    	preparator.prepareHandshakeMessageContents();
    	assertEquals(ArrayConverter.hexStringToByteArray("AABBCCDDEE"), message.getG().getByteArray());
    	assertEquals(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"), message.getP().getByteArray());
    	assertEquals(ArrayConverter.hexStringToByteArray("AABBCCDD"), message.getComputations().getClientRandom().getValue());
    	assertEquals(ArrayConverter.hexStringToByteArray("AABBCCDD"), message.getComputations().getServerRandom().getValue());
    	assertEquals(SignatureAlgorithm.RSA, message.getSignatureAlgorithm().getValue());
    	assertEquals(HashAlgorithm.SHA1, message.getHashAlgorithm().getValue());
    	assertNotNull(message.getSignature().getValue());
    	assertNotNull(message.getSignatureLength().getValue());
    }

}
