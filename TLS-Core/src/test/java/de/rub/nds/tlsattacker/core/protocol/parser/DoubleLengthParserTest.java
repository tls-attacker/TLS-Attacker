/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import org.junit.Assert;
import org.junit.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;

public class DoubleLengthParserTest {

    /**
     * Test parsing of ClientHello message with a Length field of 100, but a message length of 643.
     */
    @SuppressWarnings("SpellCheckingInspection")
    @Test
    public void testClientHelloMessageLengthTooShort() {
        Config config = Config.createConfig();
        ClientHelloParser parser = new ClientHelloParser(0, ArrayConverter.hexStringToByteArray(
            "010000640303D247A8EE60B420BB3851D9D47ACB933DBE70399BF6C92DA33AF01D4FB770E98C00025A000A002F00010002003C003D00350041008400070009009600040005C09CC09D009C009D000D001000130016001700190018001A001B003000310032003300340036003700380039003AC003C004C005C008C009C00AC00DC00EC00FC012C013C014C027C024C02800A100A000A500A600A7009E009F0067006B006C006D0015C09EC09F009A0045008800A200A30066C031C032C011C02FC030C02DC02EC02BC02CC0ACC0AD13011302008CC0AAC0ABC0AB008B00AEC0A4C0A800A8008D00AFC0A5C0A900A9008A008F0090C0A600AA009100B3C0A700AB008EC034C035C023C036C038C033000F003F004300480049004A0068006900860092009300940095009800AC00AD00B200B600B700BA00BC00BE00C000C200C4C002C007C00CC015C01DC020C025C026C029C02AC037C03CC03DC048C049C04AC04BC04CC04DC04EC04FC050C051C052C053C054C055C05CC05DC05EC05FC060C061C062C063C064C065C066C067C068C069C06AC06BC06CC06DC06EC06FC070C071C072C073C074C075C076C077C078C079C07AC07BC07CC07DC07EC07FC086C087C088C089C08AC08BC08CC08DC08EC08FC090C091C092C093C094C095C096C097C098C099C09AC09B002C002D002E003B004700B000B100B400B500B800B9C001C006C00BC010C039C03AC03B000C0012003E0040004200440046005700580059005A006A00850087008900970099009B00A400BB00BD00BF00C100C300C5C016C017C018C019C03EC03FC040C041C042C043C044C045C046C047C056C057C058C059C05AC05BC080C081C082C083C084C08500810083FF85FF87CCAACCA9CCA801000000"),
            ProtocolVersion.TLS12, config);
        try {
            config.setThrowExceptionOnParserContextViolation(true);
            parser.parse();
            Assert.fail("Expected ParserException");
        } catch (ParserException e) {
            Assert.assertEquals(
                "Attempt to parse over boundary Message Length while in context Message, boundary only has 63 bytes left, but parse request was for 602 bytes in MessageParserBoundaryContext [boundary=100, boundaryQualifier=Message Length, pointerOffset=4]",
                e.getMessage());
        }
    }
}
