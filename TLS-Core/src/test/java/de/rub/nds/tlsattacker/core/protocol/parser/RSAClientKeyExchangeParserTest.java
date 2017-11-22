/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class RSAClientKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ArrayConverter
                                        .hexStringToByteArray("100001020100dda7c19f09a87558e10eff5d9dfc1cda6f189959ea3771b872601ff02bcda22cf6b252a4c57c6c26c211289e8fd1fc24386f65ac80e66bc540b6e147b8852d1550c4bfa738aa1f090099a88ae1d8a2c80b7f78cd8e335ca70d2d35bb3f47cda0956cf3d7c5873730c31dbd7cf35409cdf9641ffc331d0384bd9165e82e4ee8518e1cb9b56121b94bfd2facbb6d0f7c107e76f7f04d3591e52cfe2f25387c9bc21c4176ffeb6fff10c09dd11dacf434949b760a3122a462010081cac196fb375f565dc94faf16c317388e797c45b6bb06d283ba4a6259712cd4a443b97ed9129407fc64dbe5134040f3374860f0b6f443365446a980e29841a8b6e3569b5929f6"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                258,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("dda7c19f09a87558e10eff5d9dfc1cda6f189959ea3771b872601ff02bcda22cf6b252a4c57c6c26c211289e8fd1fc24386f65ac80e66bc540b6e147b8852d1550c4bfa738aa1f090099a88ae1d8a2c80b7f78cd8e335ca70d2d35bb3f47cda0956cf3d7c5873730c31dbd7cf35409cdf9641ffc331d0384bd9165e82e4ee8518e1cb9b56121b94bfd2facbb6d0f7c107e76f7f04d3591e52cfe2f25387c9bc21c4176ffeb6fff10c09dd11dacf434949b760a3122a462010081cac196fb375f565dc94faf16c317388e797c45b6bb06d283ba4a6259712cd4a443b97ed9129407fc64dbe5134040f3374860f0b6f443365446a980e29841a8b6e3569b5929f6"),
                                ProtocolVersion.TLS12 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("100001020100059891a29f59797afbdd524e8f2526b2ef5c69cfef023b4a55e44caebc9d5daccdb0506567f90e9d224a0483b73b59d2cf034de212e00e5edb03a3dff042c9decc845fe6a0e89ddcf00b08c1c8929278bb35d1da39aaf930e7ac6ee9732a97ef22b74c14022e746a9f56ed6563c940bf57d60a021c177d82505483fb0f149f46704199f5db7c951301fc51cabb61a7c28cd0de8f6073dcf37bf465e01344c2d1e05008c3b84c288bdefa1a2962d7f3338cbc55e1489d04e03912ed02024fc67ecbe6f669f6b5a3d8390197d8c0c870420158b23a73da66797c50c435d916e1cfc2e696fd7b5ea4e6ca53f92c73bc6ae9a54b2d246e45942a3cc447738cd25495"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                258,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("059891a29f59797afbdd524e8f2526b2ef5c69cfef023b4a55e44caebc9d5daccdb0506567f90e9d224a0483b73b59d2cf034de212e00e5edb03a3dff042c9decc845fe6a0e89ddcf00b08c1c8929278bb35d1da39aaf930e7ac6ee9732a97ef22b74c14022e746a9f56ed6563c940bf57d60a021c177d82505483fb0f149f46704199f5db7c951301fc51cabb61a7c28cd0de8f6073dcf37bf465e01344c2d1e05008c3b84c288bdefa1a2962d7f3338cbc55e1489d04e03912ed02024fc67ecbe6f669f6b5a3d8390197d8c0c870420158b23a73da66797c50c435d916e1cfc2e696fd7b5ea4e6ca53f92c73bc6ae9a54b2d246e45942a3cc447738cd25495"),
                                ProtocolVersion.TLS11 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("100001020100cccf06b7672e22591d90fdcff119a6966432475187607b2a420ad0e573540725016f2b05dea5a0d1d3bc3a1d64f7364a061965f9299b81c67fc49b1b6161ed2724c3ded7867f56be96e5141510dcadece2d5487336f8719b136f02b939ef9268f845a47eb6842b087e1e0317d1953e95c4d5d4c80fade6911d8885ebe9f7b7adb19f5b1bda81ceffe59686a77d1fb9274a4361db3227716377d4ad881118ce92fe95934d46ec8427181e731751a69d341ff663245874d9e96b608bd661fde04676538c807d76c524ee56a94e72746cce2fac8c0267ca44bc69032a7879db4ea3ab2d18d711a0ee6892d0daf17bac446a587a94eeb4c8c56f8fdae28511070a75"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                258,
                                256,
                                ArrayConverter
                                        .hexStringToByteArray("cccf06b7672e22591d90fdcff119a6966432475187607b2a420ad0e573540725016f2b05dea5a0d1d3bc3a1d64f7364a061965f9299b81c67fc49b1b6161ed2724c3ded7867f56be96e5141510dcadece2d5487336f8719b136f02b939ef9268f845a47eb6842b087e1e0317d1953e95c4d5d4c80fade6911d8885ebe9f7b7adb19f5b1bda81ceffe59686a77d1fb9274a4361db3227716377d4ad881118ce92fe95934d46ec8427181e731751a69d341ff663245874d9e96b608bd661fde04676538c807d76c524ee56a94e72746cce2fac8c0267ca44bc69032a7879db4ea3ab2d18d711a0ee6892d0daf17bac446a587a94eeb4c8c56f8fdae28511070a75"),
                                ProtocolVersion.TLS10 },
                        {
                                ArrayConverter
                                        .hexStringToByteArray("100000801a4dc552ddd7e1e25dbaff38dd447b3a6fdc85120e2f760fefdab88e5adbbc710f3d0843f07c9f4f5ac01bc4cea02c4030c272074aa04b1b80a71123b73ea4efbe928b54a83fe4b39472bf66a953c7dc11cfb13ea08f92047996799ce702eb72a7c69bdfd98b91a09bcb836414752d93d3641740f8ed5cfff682225434052230"),
                                HandshakeMessageType.CLIENT_KEY_EXCHANGE,
                                128,
                                128,
                                ArrayConverter
                                        .hexStringToByteArray("1a4dc552ddd7e1e25dbaff38dd447b3a6fdc85120e2f760fefdab88e5adbbc710f3d0843f07c9f4f5ac01bc4cea02c4030c272074aa04b1b80a71123b73ea4efbe928b54a83fe4b39472bf66a953c7dc11cfb13ea08f92047996799ce702eb72a7c69bdfd98b91a09bcb836414752d93d3641740f8ed5cfff682225434052230"),
                                ProtocolVersion.SSL3 } });
    }

    private final byte[] message;

    private final HandshakeMessageType type;
    private final int length;

    private final int serializedKeyLength;
    private final byte[] serializedKey;
    private final ProtocolVersion version;

    public RSAClientKeyExchangeParserTest(byte[] message, HandshakeMessageType type, int length,
            int serializedKeyLength, byte[] serializedKey, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.version = version;
    }

    /**
     * Test of parse method, of class RSAClientKeyExchangeParser.
     */
    @Test
    public void testParse() {
        RSAClientKeyExchangeParser<RSAClientKeyExchangeMessage> parser = new RSAClientKeyExchangeParser(0, message,
                version);
        RSAClientKeyExchangeMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertEquals(length, msg.getLength().getValue().intValue());
        assertEquals(type.getValue(), msg.getType().getValue().byteValue());
        assertEquals(serializedKeyLength, msg.getPublicKeyLength().getValue().intValue());
        assertArrayEquals(serializedKey, msg.getPublicKey().getValue());
    }

}
