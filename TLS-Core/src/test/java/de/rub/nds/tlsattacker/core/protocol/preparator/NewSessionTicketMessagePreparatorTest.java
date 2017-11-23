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
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsattacker.util.FixedTimeProvider;
import de.rub.nds.tlsattacker.util.TimeHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketMessagePreparatorTest {

    private TlsContext context;
    private NewSessionTicketMessage message;
    private NewSessionTicketMessagePreparator preparator;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new NewSessionTicketMessage(true);
        this.preparator = new NewSessionTicketMessagePreparator(context.getChooser(), message);
    }

    @After
    public void cleanUp() {
        RandomHelper.setRandom(null);
        TimeHelper.setProvider(null);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * NewSessionTicketMessagePreparator.
     */
    @Test
    public void testPrepare() {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
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
                        .hexStringToByteArray("804cd7dedba2be6634ecd0754181608e7ead4e6b76d8d55656e476b22af4dfa66e86b6ee5adb24b31318761a64662dd0efbc13fc2d19b6a5df5f9db7d1ee3a10"));

        // Revert encryption to check the correct encryption
        // Correct value was assembled by hand because I found no testdata
        byte[] decrypted = StaticTicketCrypto.decrypt(CipherAlgorithm.AES_128_CBC, message.getTicket()
                .getEncryptedState().getValue(), context.getChooser().getConfig().getSessionTicketKeyAES(), message
                .getTicket().getIV().getValue());
        assertArrayEquals(
                decrypted,
                ArrayConverter
                        .hexStringToByteArray("0304009c0053657373696f6e5469636b65744d532b53657373696f6e5469636b65744d532b53657373696f6e5469636b65744d532b0009111119"));

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
                ArrayConverter.hexStringToByteArray("4d99650c43e222d4f10c984451f33c0f2bc5b439e92a21646cc2ff711c347ad6"));

        byte[] macinput = ArrayConverter.concatenate(message.getTicket().getKeyName().getValue(), message.getTicket()
                .getIV().getValue());
        macinput = ArrayConverter.concatenate(macinput, ArrayConverter.intToBytes(message.getTicket()
                .getEncryptedState().getValue().length, HandshakeByteLength.ENCRYPTED_STATE_LENGTH));
        macinput = ArrayConverter.concatenate(macinput, message.getTicket().getEncryptedState().getValue());
        assertTrue(StaticTicketCrypto.verifyHMAC(MacAlgorithm.HMAC_SHA256, message.getTicket().getMAC().getValue(),
                macinput, context.getChooser().getConfig().getSessionTicketKeyHMAC()));
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}