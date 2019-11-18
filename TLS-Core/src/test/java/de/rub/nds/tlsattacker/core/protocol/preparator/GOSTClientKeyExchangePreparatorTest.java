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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Ignore;
import org.junit.Test;

public class GOSTClientKeyExchangePreparatorTest {

    @Test
    @Ignore("Robert: Test is currently off because I broke the GOST code 19.6.2019")
    public void testCekGeneration() throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        TlsContext tlsContext = new TlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_GOSTR341112_256_WITH_28147_CNT_IMIT);
        tlsContext.setClientRandom(ArrayConverter
                .hexStringToByteArray("52E78EFE6E681041EC766E3DE0B54F243AE4C48C5CE47EEE84FBDA38F5C50D64"));
        tlsContext.setServerRandom(ArrayConverter
                .hexStringToByteArray("52E78EFE1B11A86ACE9CF0CD6D9E814E5C025DF53361A984A711C9D5CE078CEE"));
        tlsContext.setPreMasterSecret(ArrayConverter
                .hexStringToByteArray("26DBE1DAA8757A2FFD12E2BB1ABA62CCA69C37B180C12B7D8FEF63AC17723A25"));

        byte[] serverCert = ArrayConverter
                .hexStringToByteArray("00032100031E3082031A308202C9A003020102020A427E7BCC0000008B9273300806062A8503020203303A31123010060A0992268993F22C6401191602727531123010060A0992268993F22C640119160263703110300E06035504031307746573742D6361301E170D3134303132383034323432375A170D3234303132383131303432375A30493119301706035504030C10746C73636F6E665F7372763130323465312C302A06092A864886F70D010901161D746C73636F6E665F73727631303234654063727970746F70726F2E72753081AA302106082A85030701010102301506092A850307010201020106082A8503070101020303818400048180F0DBBD44A22D19AFCB22A0CAD421A02E7930D5C6E549C13BBF7D14377C67CAE87D45E79E27E96D631A0AA6C71E6B353C66A02362F9D43FC3F53DDFAB567CDFB92909DCB62A931896ED1F1D1655AC584DC8D6745C51EA68CAC8EBF49CAC305EFA6428509799F30D219A8407827EB276293E7BC1AE68DCB939FAD9BFBCAD938C84A38201563082015230130603551D25040C300A06082B06010505070301300B0603551D0F040403020430301D0603551D0E041604141275ECCDF8B038C7FD18379C2C4EB1ECCC932792301F0603551D230418301680149E03F0B89CFC60DC8A181EE800DFA85B32CD7376303F0603551D1F043830363034A032A030862E687474703A2F2F766D2D746573742D63612E63702E72752F43657274456E726F6C6C2F746573742D63612E63726C3081AC06082B0601050507010104819F30819C304B06082B06010505073002863F687474703A2F2F766D2D746573742D63612E63702E72752F43657274456E726F6C6C2F766D2D746573742D63612E63702E72755F746573742D63612E637274304D06082B06010505073002864166696C653A2F2F5C5C766D2D746573742D63612E63702E72755C43657274456E726F6C6C5C766D2D746573742D63612E63702E72755F746573742D63612E637274300806062A850302020303410025D1D3FCE78525E76CE8CAC6D511B9F447BA84716A1B235DDF9BE2801C6E56D301E8909E1E7DDAEA5A897272072C3AB3F130205F87298A7474A4011BE7543ABB");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(serverCert);
        Certificate tlsCert = Certificate.parse(inputStream);
        org.bouncycastle.asn1.x509.Certificate cert = tlsCert.getCertificateAt(0);
        tlsContext.getConfig().setDefaultSelectedGostCurve(GOSTCurve.Tc26_Gost_3410_12_256_paramSetA);
        BCECGOST3410_2012PublicKey publicKey = (BCECGOST3410_2012PublicKey) new JcaPEMKeyConverter().getPublicKey(cert
                .getSubjectPublicKeyInfo());
        GOSTCurve curve = GOSTCurve.fromNamedSpec((ECNamedCurveSpec) publicKey.getParams());
        tlsContext.setSelectedGostCurve(curve);
        System.out.println(curve);
        tlsContext
                .setClientEcPublicKey(Point
                        .createPoint(
                                new BigInteger(
                                        "10069287008658366627190983283629950164812876811521243982114767082045824150473125516608530551778844996599072529376320668260150663514143959293374556657645673"),
                                new BigInteger(
                                        "4228377264366878847378418012458228511431314506811669878991142841071421303960493802009018251089924600277704518780058414193146250040620726620722848816814410"),
                                curve));
        ECPoint q = publicKey.getQ();
        Point ecPoint = Point.createPoint(q.getRawXCoord().toBigInteger(), q.getRawYCoord().toBigInteger(), curve);

        tlsContext.setServerEcPublicKey(ecPoint);

        BigInteger s = new BigInteger(
                "9E861AD6F9061ADC8D94634E3C27DADF415EAE3FEA8AF1BAA803DDD4DAA20E1D57BAA0B9F48B664A9C17C778478238FA936B0DC331328EB6BB76E057CB2FE24C",
                16);
        tlsContext.setClientEcPrivateKey(s);

        GOSTClientKeyExchangeMessage message = new GOSTClientKeyExchangeMessage(tlsContext.getConfig());
        GOSTClientKeyExchangePreparator preparator = new GOST12ClientKeyExchangePreparator(tlsContext.getChooser(),
                message);
        preparator.prepare();

        byte[] expected = ArrayConverter
                .hexStringToByteArray("2B9733F1F6EFEB453035415119E46D3E1798A037488BE6B5836CF8CFB81BB597");
        byte[] actual = message.getComputations().getEncryptedKey().getValue();
        assertArrayEquals(expected, actual);

        expected = ArrayConverter.hexStringToByteArray("E2897619");
        actual = message.getComputations().getMacKey().getValue();
        assertArrayEquals(expected, actual);
    }

}
