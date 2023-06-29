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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class SSL2ServerHelloParserTest
        extends AbstractProtocolMessageParserTest<SSL2ServerHelloMessage, SSL2ServerHelloParser> {

    public SSL2ServerHelloParserTest() {
        super(
                SSL2ServerHelloMessage.class,
                SSL2ServerHelloParser::new,
                List.of(
                        Named.of(
                                "SSL2ServerHelloMessage::getSessionIdHit",
                                SSL2ServerHelloMessage::getSessionIdHit),
                        Named.of(
                                "SSL2ServerHelloMessage::getCertificateType",
                                SSL2ServerHelloMessage::getCertificateType),
                        Named.of(
                                "SSL2ServerHelloMessage::getProtocolVersion",
                                SSL2ServerHelloMessage::getProtocolVersion),
                        Named.of(
                                "SSL2ServerHelloMessage::getCertificateLength",
                                SSL2ServerHelloMessage::getCertificateLength),
                        Named.of(
                                "SSL2ServerHelloMessage::getCipherSuitesLength",
                                SSL2ServerHelloMessage::getCipherSuitesLength),
                        Named.of(
                                "SSL2ServerHelloMessage::getSessionIdLength",
                                SSL2ServerHelloMessage::getSessionIdLength),
                        Named.of(
                                "SSL2ServerHelloMessage::getCertificate",
                                SSL2ServerHelloMessage::getCertificate),
                        Named.of(
                                "SSL2ServerHelloMessage::getCipherSuites",
                                SSL2ServerHelloMessage::getCipherSuites),
                        Named.of(
                                "SSL2ServerHelloMessage::getSessionId",
                                SSL2ServerHelloMessage::getSessionId)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ProtocolVersion.SSL2,
                        ArrayConverter.hexStringToByteArray(
                                "0001000201ed00060010308201e930820152020106300d06092a864886f70d0101040500305b310b3009060355040613024155311330110603550408130a517565656e736c616e64311a3018060355040a13114372797074536f667420507479204c7464311b301906035504031312546573742043412028313032342062697429301e170d3030313031363232333130335a170d3033303131343232333130335a3063310b3009060355040613024155311330110603550408130a517565656e736c616e64311a3018060355040a13114372797074536f667420507479204c7464312330210603550403131a5365727665722074657374206365727420283531322062697429305c300d06092a864886f70d0101010500034b0030480241009fb3c3842795ff1231520f15ef4611c4ad80e6365b0fdd80d7618de0fc72450934fe556645434c68976afea8a0a5df5f78ffeed764b83f04cb6fff2afefeb9ed0203010001300d06092a864886f70d01010405000381810093d20ac541e65aa986f91187e4db45e2c595781a6c806d731fb46d44a3ba8688c858cd1c06356c446288dfe4f6646195ef4aa67f6571d76b8839f632bfac936769518c93ec485fc9b142f955d27e4ef4f2216b9057e6d7999e41ca80bf1a28a2ca5b504aed84e782c7d2cf369e6a67b988a7f38ad004f8e8c617e3c529bc17f10400800200807aa9b1cbab16a84bd99416f443587d0c"),
                        Arrays.asList(
                                (byte) 0x00,
                                (byte) 0x01,
                                ProtocolVersion.SSL2.getValue(),
                                0x01ed,
                                0x0006,
                                0x0010,
                                ArrayConverter.hexStringToByteArray(
                                        "308201e930820152020106300d06092a864886f70d0101040500305b310b3009060355040613024155311330110603550408130a517565656e736c616e64311a3018060355040a13114372797074536f667420507479204c7464311b301906035504031312546573742043412028313032342062697429301e170d3030313031363232333130335a170d3033303131343232333130335a3063310b3009060355040613024155311330110603550408130a517565656e736c616e64311a3018060355040a13114372797074536f667420507479204c7464312330210603550403131a5365727665722074657374206365727420283531322062697429305c300d06092a864886f70d0101010500034b0030480241009fb3c3842795ff1231520f15ef4611c4ad80e6365b0fdd80d7618de0fc72450934fe556645434c68976afea8a0a5df5f78ffeed764b83f04cb6fff2afefeb9ed0203010001300d06092a864886f70d01010405000381810093d20ac541e65aa986f91187e4db45e2c595781a6c806d731fb46d44a3ba8688c858cd1c06356c446288dfe4f6646195ef4aa67f6571d76b8839f632bfac936769518c93ec485fc9b142f955d27e4ef4f2216b9057e6d7999e41ca80bf1a28a2ca5b504aed84e782c7d2cf369e6a67b988a7f38ad004f8e8c617e3c529bc17f1"),
                                ArrayConverter.hexStringToByteArray("040080020080"),
                                ArrayConverter.hexStringToByteArray(
                                        "7aa9b1cbab16a84bd99416f443587d0c"))));
    }
}
