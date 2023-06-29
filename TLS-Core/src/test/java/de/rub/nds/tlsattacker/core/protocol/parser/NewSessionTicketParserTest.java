/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class NewSessionTicketParserTest
        extends AbstractHandshakeMessageParserTest<
                NewSessionTicketMessage, NewSessionTicketParser> {

    public NewSessionTicketParserTest() {
        super(
                NewSessionTicketMessage.class,
                NewSessionTicketParser::new,
                List.of(
                        Named.of(
                                "NewSessionTicketMessage::getTicket::getIdentity",
                                msg -> msg.getTicket().getIdentity()),
                        Named.of(
                                "NewSessionTicketMessage::getTicket::getTicketNonce",
                                msg -> msg.getTicket().getTicketNonce()),
                        Named.of(
                                "NewSessionTicketMessage::getTicket::getTicketAgeAdd",
                                msg -> msg.getTicket().getTicketAgeAdd()),
                        Named.of(
                                "NewSessionTicketMessage::getTicketLifetimeHint",
                                NewSessionTicketMessage::getTicketLifetimeHint)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.TLS11,
                        ArrayConverter.hexStringToByteArray(
                                "040000a600001c2000a04c1ffe5c9ce499974ccb74375751f927457820fc83573a62c9c878781e0edde8eae72e472948aa05a224a1dbc47f9e9f1e1d93689c2321dcb62d99f6bd7cd8018f3039bb0cf6c2d74f50d81861001bf27f1aa657426293c24a77be9083176cda9fc9de3f0ee3a4b8bb53c6cf41ed4a1af299063c67267eee257c598d885d4a8a322ecf4ad521f787c1a2119d81acd45373f2299f32c2b49b4c583c85eda5e7e3"),
                        Arrays.asList(
                                HandshakeMessageType.NEW_SESSION_TICKET.getValue(),
                                166,
                                ArrayConverter.hexStringToByteArray(
                                        "4c1ffe5c9ce499974ccb74375751f927457820fc83573a62c9c878781e0edde8eae72e472948aa05a224a1dbc47f9e9f1e1d93689c2321dcb62d99f6bd7cd8018f3039bb0cf6c2d74f50d81861001bf27f1aa657426293c24a77be9083176cda9fc9de3f0ee3a4b8bb53c6cf41ed4a1af299063c67267eee257c598d885d4a8a322ecf4ad521f787c1a2119d81acd45373f2299f32c2b49b4c583c85eda5e7e3"),
                                null,
                                null,
                                7200L)),
                Arguments.of(
                        ProtocolVersion.TLS12,
                        ArrayConverter.hexStringToByteArray(
                                "040000a600001c2000a0f11456af91d9738d6dc7ece4b8f03430ec511de863c52bced5cfec3791784997ea7aaec9cabf0c6b782cb0f93f92c31111895bd85cf84af0a95ed8e021497cd0a99dbd501a8fb003e013f540e0a76e89aba5b17094f8f5427375fd274d93f4ac84e754a3959091686a9b51eac65d6d5e74adda93274d14d18ee16097f97eb6cce6b423b2474237118aaaf777ddd95b8870de122d4dd0a48a18b27bfa077ad644"),
                        Arrays.asList(
                                HandshakeMessageType.NEW_SESSION_TICKET.getValue(),
                                166,
                                ArrayConverter.hexStringToByteArray(
                                        "f11456af91d9738d6dc7ece4b8f03430ec511de863c52bced5cfec3791784997ea7aaec9cabf0c6b782cb0f93f92c31111895bd85cf84af0a95ed8e021497cd0a99dbd501a8fb003e013f540e0a76e89aba5b17094f8f5427375fd274d93f4ac84e754a3959091686a9b51eac65d6d5e74adda93274d14d18ee16097f97eb6cce6b423b2474237118aaaf777ddd95b8870de122d4dd0a48a18b27bfa077ad644"),
                                null,
                                null,
                                7200L)),
                Arguments.of(
                        ProtocolVersion.TLS13,
                        ArrayConverter.hexStringToByteArray(
                                "040000e500001c20bc3dca2b08000000000000000000d0f11456af91d9738d6dc7ece4b8f0343044cbb3c1f1e763c0e80d49010c72c4e5b2ec293432abfaa30caa461237febee09c5a3a8a5df4d5401d5e825e897a388bb4543c635d07cc44f7f4dcf6d0841ec4f4ece40ffd2fbd8435ca361288786211e021c4d70985895962e90952c0755ad2f0bd345e2b84adc1335461e7aa92b71af3e52c46d07543ab08e7ea214c321d6b0b5eb568fa45f8b708cbefa0106c97f4e71117a208510b5e40c0ace15fa533ab5fdde3cca86cff47b4461093270b1e343ddd007b2aba3d321c6b7f3d2e64e1220000"),
                        List.of(
                                HandshakeMessageType.NEW_SESSION_TICKET.getValue(),
                                229,
                                ArrayConverter.hexStringToByteArray(
                                        "f11456af91d9738d6dc7ece4b8f0343044cbb3c1f1e763c0e80d49010c72c4e5b2ec293432abfaa30caa461237febee09c5a3a8a5df4d5401d5e825e897a388bb4543c635d07cc44f7f4dcf6d0841ec4f4ece40ffd2fbd8435ca361288786211e021c4d70985895962e90952c0755ad2f0bd345e2b84adc1335461e7aa92b71af3e52c46d07543ab08e7ea214c321d6b0b5eb568fa45f8b708cbefa0106c97f4e71117a208510b5e40c0ace15fa533ab5fdde3cca86cff47b4461093270b1e343ddd007b2aba3d321c6b7f3d2e64e122"),
                                ArrayConverter.hexStringToByteArray("0000000000000000"),
                                ArrayConverter.hexStringToByteArray("bc3dca2b"),
                                7200L)));
    }
}
