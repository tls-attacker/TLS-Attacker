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
import de.rub.nds.modifiablevariable.util.BadFixedRandom;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class NewSessionTicketPreparatorTest {

    private TlsContext context;
    private NewSessionTicketMessage message;
    private NewSessionTicketPreparator preparator;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new NewSessionTicketMessage(true);
        this.preparator = new NewSessionTicketPreparator(context.getChooser(), message);
    }

    @After
    public void cleanUp() {
        RandomHelper.setRandom(null);
        TimeHelper.setProvider(null);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * NewSessionTicketPreparator.
     * 
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testPrepare() throws CryptoException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        context.setSelectedCompressionMethod(CompressionMethod.NULL);
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("53657373696f6e5469636b65744d532b53657373696f6e5469636b65744d532b53657373696f6e5469636b65744d532b")); // SessionTicketMS+SessionTicketMS+SessionTicketMS+
        context.setClientAuthentication(false);
        TimeHelper.setProvider(new FixedTimeProvider(152113433000l)); // 0x09111119
        context.getConfig().setSessionTicketLifetimeHint(3600); // 3600 = 0xe10

        RandomHelper.setRandom(new BadFixedRandom((byte) 0x55));
        preparator.prepare();

        // Check ticketdata
        // Correct value was calculated by http://aes.online-domain-tools.com/
        assertArrayEquals(
                message.getTicket().getEncryptedState().getValue(),
                ArrayConverter
                        .hexStringToByteArray("23403433756E7E6C0777047BECA5B4A1FC987804A39B420BE56DA996D6F9C233CC6C97FC2F5A3EE3A193A2ACE6F320E6AA3E98B66B4A3C51AA4056D7EF5898F8"));

        // Revert encryption to check the correct encryption
        // Correct value was assembled by hand because I found no testdata
        byte[] decrypted = StaticTicketCrypto.decrypt(CipherAlgorithm.AES_128_CBC, message.getTicket()
                .getEncryptedState().getValue(), context.getChooser().getConfig().getSessionTicketKeyAES(), message
                .getTicket().getIV().getValue());
        assertArrayEquals(
                decrypted,
                ArrayConverter
                        .hexStringToByteArray("0303009c0053657373696f6e5469636b65744d532b53657373696f6e5469636b65744d532b53657373696f6e5469636b65744d532b0009111119"));

        // Smaller Tests to be complete
        assertTrue(message.getTicketLifetimeHint().getValue() == 3600);
        assertTrue(message.getTicketLength().getValue() == 128);
        assertArrayEquals(message.getTicket().getIV().getValue(),
                ArrayConverter.hexStringToByteArray("55555555555555555555555555555555"));
        assertArrayEquals(message.getTicket().getKeyName().getValue(),
                ArrayConverter.hexStringToByteArray("544c532d41747461636b6572204b6579"));

        // Correct value was assembled by hand and calculated by
        // https://www.liavaag.org/English/SHA-Generator/HMAC/
        assertArrayEquals(message.getTicket().getMAC().getValue(),
                ArrayConverter.hexStringToByteArray("C12AC5FD8690B8E61F647F86630271F16C9A6281663014C2873EE4934A6C9C3B"));

        byte[] macinput = ArrayConverter.concatenate(message.getTicket().getKeyName().getValue(), message.getTicket()
                .getIV().getValue());
        macinput = ArrayConverter.concatenate(macinput, ArrayConverter.intToBytes(message.getTicket()
                .getEncryptedState().getValue().length, HandshakeByteLength.ENCRYPTED_STATE_LENGTH));
        macinput = ArrayConverter.concatenate(macinput, message.getTicket().getEncryptedState().getValue());
        assertTrue(StaticTicketCrypto.verifyHMAC(MacAlgorithm.HMAC_SHA256, message.getTicket().getMAC().getValue(),
                macinput, context.getChooser().getConfig().getSessionTicketKeyHMAC()));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}