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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.*;

@SuppressWarnings("SpellCheckingInspection")
@RunWith(Parameterized.class)
public class CertificateStatusMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray(
            "160002130100020F3082020B0A0100A08202043082020006092B0601050507300101048201F1308201ED3081D6A14C304A310B300906035504061302555331163014060355040A130D4C6574277320456E6372797074312330210603550403131A4C6574277320456E637279707420417574686F72697479205833180F32303230303631353135353930305A30753073304B300906052B0E03021A050004147EE66AE7729AB3FCF8A220646C16A12D6071085D0414A84A6A63047DDDBAE6D139B7A64565EFF3A8ECA1021204A2913B04A98CA8F47D8817CB259FBE6C338000180F32303230303631353135303030305AA011180F32303230303632323135303030305A300D06092A864886F70D01010B050003820101009BC0EDEB1C98395CE545FBA89A1C4742DB92E84941235CFFE5DEE4B3D428E724FCA980A481B63DCA5ADC8F18AD328BB3B36F702FA1897485220D623E56066B7D81FF3F45A12853415DE0657BC129989F7710158A532815D141EB290B1685074D1C111CF40687AFEAB392CAA72715F9CC8EC4A23B8640F1269BFA7C49DC1142F01EFB402C612619BF1193D5F9D3D4B7BE04C79D9998EE4780A0ADDB54FFA7F3E6F5140D51151E0D3E9F06DF77654EFA36FD7D1A22F704BFDD646C89D8CD36814677E08B9BC5ACD3751F663B9D0BB1C69E973E029176BC825C79A2555AC03F835124E61D5E63E381C6F3210E738E390CB5213977C011441B1BF8141D6B9BE05EBC"),
            HandshakeMessageType.CERTIFICATE_STATUS, 531, 1, 527,
            ArrayConverter.hexStringToByteArray(
                "3082020B0A0100A08202043082020006092B0601050507300101048201F1308201ED3081D6A14C304A310B300906035504061302555331163014060355040A130D4C6574277320456E6372797074312330210603550403131A4C6574277320456E637279707420417574686F72697479205833180F32303230303631353135353930305A30753073304B300906052B0E03021A050004147EE66AE7729AB3FCF8A220646C16A12D6071085D0414A84A6A63047DDDBAE6D139B7A64565EFF3A8ECA1021204A2913B04A98CA8F47D8817CB259FBE6C338000180F32303230303631353135303030305AA011180F32303230303632323135303030305A300D06092A864886F70D01010B050003820101009BC0EDEB1C98395CE545FBA89A1C4742DB92E84941235CFFE5DEE4B3D428E724FCA980A481B63DCA5ADC8F18AD328BB3B36F702FA1897485220D623E56066B7D81FF3F45A12853415DE0657BC129989F7710158A532815D141EB290B1685074D1C111CF40687AFEAB392CAA72715F9CC8EC4A23B8640F1269BFA7C49DC1142F01EFB402C612619BF1193D5F9D3D4B7BE04C79D9998EE4780A0ADDB54FFA7F3E6F5140D51151E0D3E9F06DF77654EFA36FD7D1A22F704BFDD646C89D8CD36814677E08B9BC5ACD3751F663B9D0BB1C69E973E029176BC825C79A2555AC03F835124E61D5E63E381C6F3210E738E390CB5213977C011441B1BF8141D6B9BE05EBC"),
            ProtocolVersion.TLS12 }, });
    }

    private byte[] message;
    private HandshakeMessageType type;
    private int length;
    private int certificateStatusType;
    private int ocspResponseLength;
    private byte[] ocspResponseBytes;
    private ProtocolVersion version;

    public CertificateStatusMessageParserTest(byte[] message, HandshakeMessageType type, int length,
        int certificateStatusType, int ocspResponseLength, byte[] ocspResponseBytes, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.certificateStatusType = certificateStatusType;
        this.ocspResponseLength = ocspResponseLength;
        this.ocspResponseBytes = ocspResponseBytes;
        this.version = version;
    }

    @Test
    public void testParse() {
        CertificateStatusParser parser = new CertificateStatusParser(0, message, version, Config.createConfig());
        CertificateStatusMessage msg = parser.parse();
        assertEquals((int) msg.getLength().getValue(), length);
        assertEquals((byte) msg.getType().getValue(), type.getValue());
        assertEquals((int) msg.getCertificateStatusType().getValue(), certificateStatusType);
        assertEquals((int) msg.getOcspResponseLength().getValue(), ocspResponseLength);
        assertArrayEquals(msg.getOcspResponseBytes().getValue(), ocspResponseBytes);
    }
}
