/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class NewSessionTicketParserTest {
    private final byte[] message;
    private final int start;
    private final byte[] identity;
    private final ProtocolVersion version;
    private final long lifetime;
    private final byte[] ageadd;
    private final byte[] nonce;

    private final Config config = Config.createConfig();

    private static byte[] sessionTicketTls1_1 = ArrayConverter.hexStringToByteArray(
        "040000a600001c2000a04c1ffe5c9ce499974ccb74375751f927457820fc83573a62c9c878781e0edde8eae72e472948aa05a224a1dbc47f9e9f1e1d93689c2321dcb62d99f6bd7cd8018f3039bb0cf6c2d74f50d81861001bf27f1aa657426293c24a77be9083176cda9fc9de3f0ee3a4b8bb53c6cf41ed4a1af299063c67267eee257c598d885d4a8a322ecf4ad521f787c1a2119d81acd45373f2299f32c2b49b4c583c85eda5e7e3");
    private static byte[] sessionTicketTls1_1_identity = ArrayConverter.hexStringToByteArray(
        "4c1ffe5c9ce499974ccb74375751f927457820fc83573a62c9c878781e0edde8eae72e472948aa05a224a1dbc47f9e9f1e1d93689c2321dcb62d99f6bd7cd8018f3039bb0cf6c2d74f50d81861001bf27f1aa657426293c24a77be9083176cda9fc9de3f0ee3a4b8bb53c6cf41ed4a1af299063c67267eee257c598d885d4a8a322ecf4ad521f787c1a2119d81acd45373f2299f32c2b49b4c583c85eda5e7e3");
    private static long sessionTicketTls1_1_lifetime = 7200;
    private static byte[] sessionTicketTls1_2 = ArrayConverter.hexStringToByteArray(
        "040000a600001c2000a0f11456af91d9738d6dc7ece4b8f03430ec511de863c52bced5cfec3791784997ea7aaec9cabf0c6b782cb0f93f92c31111895bd85cf84af0a95ed8e021497cd0a99dbd501a8fb003e013f540e0a76e89aba5b17094f8f5427375fd274d93f4ac84e754a3959091686a9b51eac65d6d5e74adda93274d14d18ee16097f97eb6cce6b423b2474237118aaaf777ddd95b8870de122d4dd0a48a18b27bfa077ad644");
    private static byte[] sessionTicketTls1_2_identity = ArrayConverter.hexStringToByteArray(
        "f11456af91d9738d6dc7ece4b8f03430ec511de863c52bced5cfec3791784997ea7aaec9cabf0c6b782cb0f93f92c31111895bd85cf84af0a95ed8e021497cd0a99dbd501a8fb003e013f540e0a76e89aba5b17094f8f5427375fd274d93f4ac84e754a3959091686a9b51eac65d6d5e74adda93274d14d18ee16097f97eb6cce6b423b2474237118aaaf777ddd95b8870de122d4dd0a48a18b27bfa077ad644");
    private static long sessionTicketTls1_2_lifetime = 7200;
    private static byte[] sessionTicketTls1_3 = ArrayConverter.hexStringToByteArray(
        "040000e500001c20bc3dca2b08000000000000000000d0f11456af91d9738d6dc7ece4b8f0343044cbb3c1f1e763c0e80d49010c72c4e5b2ec293432abfaa30caa461237febee09c5a3a8a5df4d5401d5e825e897a388bb4543c635d07cc44f7f4dcf6d0841ec4f4ece40ffd2fbd8435ca361288786211e021c4d70985895962e90952c0755ad2f0bd345e2b84adc1335461e7aa92b71af3e52c46d07543ab08e7ea214c321d6b0b5eb568fa45f8b708cbefa0106c97f4e71117a208510b5e40c0ace15fa533ab5fdde3cca86cff47b4461093270b1e343ddd007b2aba3d321c6b7f3d2e64e1220000");
    private static byte[] sessionTicketTls1_3_identity = ArrayConverter.hexStringToByteArray(
        "f11456af91d9738d6dc7ece4b8f0343044cbb3c1f1e763c0e80d49010c72c4e5b2ec293432abfaa30caa461237febee09c5a3a8a5df4d5401d5e825e897a388bb4543c635d07cc44f7f4dcf6d0841ec4f4ece40ffd2fbd8435ca361288786211e021c4d70985895962e90952c0755ad2f0bd345e2b84adc1335461e7aa92b71af3e52c46d07543ab08e7ea214c321d6b0b5eb568fa45f8b708cbefa0106c97f4e71117a208510b5e40c0ace15fa533ab5fdde3cca86cff47b4461093270b1e343ddd007b2aba3d321c6b7f3d2e64e122");
    private static long sessionTicketTls1_3_lifetime = 7200;
    private static byte[] sessionTicketTls1_3_AgeAdd = ArrayConverter.hexStringToByteArray("bc3dca2b");
    private static byte[] sessionTicketTls1_3_Nonce = ArrayConverter.hexStringToByteArray("0000000000000000");

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { sessionTicketTls1_1, 0, sessionTicketTls1_1_identity, sessionTicketTls1_1_lifetime, new byte[0],
                new byte[0], ProtocolVersion.TLS11 },
            { sessionTicketTls1_2, 0, sessionTicketTls1_2_identity, sessionTicketTls1_2_lifetime, new byte[0],
                new byte[0], ProtocolVersion.TLS12 },
            { sessionTicketTls1_3, 0, sessionTicketTls1_3_identity, sessionTicketTls1_3_lifetime,
                sessionTicketTls1_3_AgeAdd, sessionTicketTls1_3_Nonce, ProtocolVersion.TLS13 } });
    }

    public NewSessionTicketParserTest(byte[] message, int start, byte[] identity, long lifetime, byte[] ageadd,
        byte[] nonce, ProtocolVersion version) {
        this.message = message;
        this.start = start;
        this.version = version;
        this.identity = identity;
        this.lifetime = lifetime;
        this.ageadd = ageadd;
        this.nonce = nonce;
    }

    @Test
    public void testParse() {
        NewSessionTicketParser parser = new NewSessionTicketParser(start, message, version, config);
        NewSessionTicketMessage msg = parser.parse();
        assertArrayEquals(identity, msg.getTicket().getIdentity().getValue());
        assertEquals(lifetime, (long) msg.getTicketLifetimeHint().getValue());
        // For TLS 1.3 also test Nonce and AgeAdd field which are not present in
        // previous versions
        if (version.equals(ProtocolVersion.TLS13)) {
            assertArrayEquals(ageadd, msg.getTicket().getTicketAgeAdd().getValue());
            assertArrayEquals(nonce, msg.getTicket().getTicketNonce().getValue());
        }
    }

}
