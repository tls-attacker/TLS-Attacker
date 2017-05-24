/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FinishedMessagePreparatorTest {

    private FinishedMessage message;
    private TlsContext context;
    private FinishedMessagePreparator preparator;

    public FinishedMessagePreparatorTest() {
    }

    @Before
    public void setUp() {
        message = new FinishedMessage();
        context = new TlsContext();
        preparator = new FinishedMessagePreparator(context, message);
    }

    /**
     * Test of prepareHandshakeMessageContents method, of class
     * FinishedMessagePreparator.
     */
    @Test
    public void testPrepare() {
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray("AABBCCDDEEFF"));
        preparator.prepare();
        LOGGER.info(ArrayConverter.bytesToHexString(message.getVerifyData().getValue(), false));
        assertArrayEquals(ArrayConverter.hexStringToByteArray("232A2CCB976E313AAA8E0F7A"), message.getVerifyData()
                .getValue());// TODO Did not check if this is calculated
                             // correctly, just made sure it is set

    }

    /**
     * Test of prepareHandshakeMessageContents method for TLS 1.3, of class
     * FinishedMessagePreparator.
     */
    @Test
    public void testPrepareTLS13() {
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.getConfig().setConnectionEnd(ConnectionEnd.SERVER);
        context.setServerHandshakeTrafficSecret(ArrayConverter
                .hexStringToByteArray("3550ca3a8c2192729cc385313e3bc83292a14f4ecb3d2b9218ea7907c67ab3a7"));
        context.getDigest()
                .setRawBytes(
                        ArrayConverter
                                .hexStringToByteArray("010001fc0303ce05cfa3d92170cbc2465cdc3e3a2f577f6eac809361708ab244b07d8fad861600003e130113031302c02bc02fcca9cca8c00ac009c013c023c027c014009eccaa00330032006700390038006b00160013009c002f003c0035003d000a0005000401000195001500fc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104000b0002010000230000002800260024001d00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c002b0007067f1203030302000d0020001e040305030603020308040805080604010501060102010402050206020202002d000201010200004e7f1220b9c9201cd171a15abba4e7eddcf3e8488e7192ffe01ea5c19f3d4b52ffeebe1301002800280024001d00209c1b0a7421919a73cb57b3a0ad9d6805861a9c47e11df8639d25323b79ce201c0800001e001c000a00140012001d00170018001901000101010201030104000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f00008408040080134e22eac57321ab47db6b38b2992cec2dd79bd065a034a9af6b9e3d03475e4309e6523ccdf055453fb480804a3a7e996229eb28e734f6702bea2b32149899ac043a4b44468197868da77147ce9f73c0543c4e3fc33e306cac8506faa80a959c5f1edccbee76eda1ad7a4fa440de35dcb87e82ec94e8725355ce7507713a609e"));
        preparator.prepare();
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("7304bb73321f01b71dd94622fae98daf634490d220e4c8f3ffa2559911a56e51"),
                message.getVerifyData().getValue());
    }

    private static final Logger LOGGER = LogManager.getLogger(FinishedMessagePreparatorTest.class);
}
