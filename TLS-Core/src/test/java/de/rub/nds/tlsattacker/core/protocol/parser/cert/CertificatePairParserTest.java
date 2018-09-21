/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.cert;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificatePairParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] {
                        {
                                ArrayConverter
                                        .hexStringToByteArray("00032916656a770ce73e582f227bfc49673b427fd0bf3d6d5212fb33f7e12715de62e56f2fda029efd617f6743bc0c850df406ad4d3fb2b820134aa375013f868253e8974de2355123fcfbffd0410e444eec0cda6d54a6ddb98d28c629344f1f1f9f9b68fcde005e3cd1fe91d702d2a41bb74b671b4c138a2d48cc30a0e3226fca5d32983ca08c71c55f60de34948e89cc2c5d267addfb81d8969ce9946e61014311a075f2f1b750142198a4d6f050cb46d2c693079cefdaaee743771004e5e32ae34d1500d6d28138c9edc8e9168eda8dfc4a0808703f38e88fb5cf5a6eb94eba0392ca75b5af168ba04ff7337bec302a0ee0266ade0a2d4d7a633b37bfc68c61dbb42762b1217d534ac07550852480a9d3fdfef9c919b584d9e25e6ca1803201008d5a14872cac8ba1080dfe0db4948aa5c1fa6835db0fa5ff44c7e79bf0eadc6e5a01ac89cf25192a8a534ddacee1838198270bff2f847144611c1f300c2d09b5f6f30efc08e1b307216efa0b05e9770269141aca9a2f449ca6d36476352b28f3ed2ff04c3fbfd0157e24698c177586aefb00227734ce13768c4df3fa78a4d295d8bef18fb2287802fce17c5f18be233033a827ee07637f2a70c4d8ae6a87890a6b40f2661cb59066096de581e460f6aaba4c4da5d09a6ae24de061b9ae52ddd027a14a2313ab38d5b9f45a292958961cac2edf1f7dfbf6b35175fc28002f1948c62e146be8de8276a89508ad2b8245ef2221b576aa972d748c2596148811cc72175812f29f1f93a42d5301a077d9fa6707436088ab9b64b5aa139e86a2be6427d2c7051a7895eba474c3427d17dd2f2072b6f06836213b96bc4aba80e97b1d5981579d87bc9d38b0ee4995e0a1220e190e880aee8c59046ec4be46b43d6c10ec7974339922cdd88be8216c5ab1635a8a830d881459c2c6917de49246fb6038121ba446535364fee81890502b76bddfeeb33c80f0496658e4977f7752d9d136009a7175b6ba403f6d110fa78c40ac7003ebf4df3321d1278c7080a6948a462dd56c3d18195ac0497d54388f076844799c86262b2eaa91331b6d2637bfd97051b3cfd7f9ce0f30a91ae0a6a757d9651f262102e965d8c70997f44d16ecec34947b983d9684f54d7cceab300001aa"),
                                809,
                                ArrayConverter
                                        .hexStringToByteArray("16656a770ce73e582f227bfc49673b427fd0bf3d6d5212fb33f7e12715de62e56f2fda029efd617f6743bc0c850df406ad4d3fb2b820134aa375013f868253e8974de2355123fcfbffd0410e444eec0cda6d54a6ddb98d28c629344f1f1f9f9b68fcde005e3cd1fe91d702d2a41bb74b671b4c138a2d48cc30a0e3226fca5d32983ca08c71c55f60de34948e89cc2c5d267addfb81d8969ce9946e61014311a075f2f1b750142198a4d6f050cb46d2c693079cefdaaee743771004e5e32ae34d1500d6d28138c9edc8e9168eda8dfc4a0808703f38e88fb5cf5a6eb94eba0392ca75b5af168ba04ff7337bec302a0ee0266ade0a2d4d7a633b37bfc68c61dbb42762b1217d534ac07550852480a9d3fdfef9c919b584d9e25e6ca1803201008d5a14872cac8ba1080dfe0db4948aa5c1fa6835db0fa5ff44c7e79bf0eadc6e5a01ac89cf25192a8a534ddacee1838198270bff2f847144611c1f300c2d09b5f6f30efc08e1b307216efa0b05e9770269141aca9a2f449ca6d36476352b28f3ed2ff04c3fbfd0157e24698c177586aefb00227734ce13768c4df3fa78a4d295d8bef18fb2287802fce17c5f18be233033a827ee07637f2a70c4d8ae6a87890a6b40f2661cb59066096de581e460f6aaba4c4da5d09a6ae24de061b9ae52ddd027a14a2313ab38d5b9f45a292958961cac2edf1f7dfbf6b35175fc28002f1948c62e146be8de8276a89508ad2b8245ef2221b576aa972d748c2596148811cc72175812f29f1f93a42d5301a077d9fa6707436088ab9b64b5aa139e86a2be6427d2c7051a7895eba474c3427d17dd2f2072b6f06836213b96bc4aba80e97b1d5981579d87bc9d38b0ee4995e0a1220e190e880aee8c59046ec4be46b43d6c10ec7974339922cdd88be8216c5ab1635a8a830d881459c2c6917de49246fb6038121ba446535364fee81890502b76bddfeeb33c80f0496658e4977f7752d9d136009a7175b6ba403f6d110fa78c40ac7003ebf4df3321d1278c7080a6948a462dd56c3d18195ac0497d54388f076844799c86262b2eaa91331b6d2637bfd97051b3cfd7f9ce0f30a91ae0a6a757d9651f262102e965d8c70997f44d16ecec34947b983d9684f54d7cceab30"),
                                1, ArrayConverter.hexStringToByteArray("aa"), },
                        { ArrayConverter.hexStringToByteArray("000002aaaa0001aa"), 2,
                                ArrayConverter.hexStringToByteArray("aaaa"), 1,
                                ArrayConverter.hexStringToByteArray("aa"), } });
    }

    private int certificateLength;
    private int extensionsLength;
    private byte[] certificate;
    private byte[] extension;
    private byte[] certpair;

    public CertificatePairParserTest(byte[] certpair, int certificateLength, byte[] certificate, int extensionsLength,
            byte[] extension) {
        this.certificateLength = certificateLength;
        this.extensionsLength = extensionsLength;
        this.certificate = certificate;
        this.extension = extension;
        this.certpair = certpair;
    }

    // Test of parse method, of class CertificatePairParser
    @Test
    public void testParse() {
        CertificatePairParser parser = new CertificatePairParser(0, certpair);
        CertificatePair pair = parser.parse();
        assertTrue(certificateLength == pair.getCertificateLength().getValue());
        assertTrue(extensionsLength == pair.getExtensionsLength().getValue());
        assertArrayEquals(certificate, pair.getCertificate().getValue());
        assertArrayEquals(extension, pair.getExtensions().getValue());
    }
}