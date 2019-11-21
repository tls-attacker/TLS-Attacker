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
import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 *
 *
 *
 */
public class ECDHEServerKeyExchangePreparatorTest {

    private TlsContext tlsContext;
    private BadRandom random;
    private ECDHEServerKeyExchangeMessage msg;
    private ECDHEServerKeyExchangePreparator preparator;

    @Before
    public void setUp() throws Exception {
        this.tlsContext = new TlsContext();
        BadFixedRandom rnd = new BadFixedRandom((byte) 0x23);
        random = new BadRandom(rnd, null);

        loadTestVectorsToContext();

        tlsContext.setRandom(random);
        msg = new ECDHEServerKeyExchangeMessage();
        preparator = new ECDHEServerKeyExchangePreparator(tlsContext.getChooser(), msg);
    }

    @After
    public void cleanUp() {
        tlsContext.setRandom(null);
    }

    @Test
    public void testPrepareHandshakeMessageContents() throws IOException {
        preparator.prepareHandshakeMessageContents();
        Certificate cert = Certificate
                .parse(new ByteArrayInputStream(
                        ArrayConverter
                                .hexStringToByteArray("0003970003943082039030820278A003020102020900A650C00794049FCD300D06092A864886F70D01010B0500305C310B30090603550406130241553113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643115301306035504030C0C544C532D41747461636B65723020170D3137303731333132353331385A180F32313137303631393132353331385A305C310B30090603550406130241553113301106035504080C0A536F6D652D53746174653121301F060355040A0C18496E7465726E6574205769646769747320507479204C74643115301306035504030C0C544C532D41747461636B657230820122300D06092A864886F70D01010105000382010F003082010A0282010100C8820D6C3CE84C8430F6835ABFC7D7A912E1664F44578751F376501A8C68476C3072D919C5D39BD0DBE080E71DB83BD4AB2F2F9BDE3DFFB0080F510A5F6929C196551F2B3C369BE051054C877573195558FD282035934DC86EDAB8D4B1B7F555E5B2FEE7275384A756EF86CB86793B5D1333F0973203CB96966766E655CD2CCCAE1940E4494B8E9FB5279593B75AFD0B378243E51A88F6EB88DEF522A8CD5C6C082286A04269A2879760FCBA45005D7F2672DD228809D47274F0FE0EA5531C2BD95366C05BF69EDC0F3C3189866EDCA0C57ADCCA93250AE78D9EACA0393A95FF9952FC47FB7679DD3803E6A7A6FA771861E3D99E4B551A4084668B111B7EEF7D0203010001A3533051301D0603551D0E04160414E7A92FE5543AEE2FF7592F800AC6E66541E3268B301F0603551D23041830168014E7A92FE5543AEE2FF7592F800AC6E66541E3268B300F0603551D130101FF040530030101FF300D06092A864886F70D01010B050003820101000D5C11E28CF19D1BC17E4FF543695168570AA7DB85B3ECB85405392A0EDAFE4F097EE4685B7285E3D9B869D23257161CA65E20B5E6A585D33DA5CD653AF81243318132C9F64A476EC08BA80486B3E439F765635A7EA8A969B3ABD8650036D74C5FC4A04589E9AC8DC3BE2708743A6CFE3B451E3740F735F156D6DC7FFC8A2C852CD4E397B942461C2FCA884C7AFB7EBEF7918D6AAEF1F0D257E959754C4665779FA0E3253EF2BEDBBD5BE5DA600A0A68E51D2D1C125C4E198669A6BC715E8F3884E9C3EFF39D40838ADA4B1F38313F6286AA395DC6DEA9DAF49396CF12EC47EFA7A0D3882F8B84D9AEEFFB252C6B81A566609605FBFD3F0D17E5B12401492A1A")));
        tlsContext.getConfig().setDefaultExplicitCertificateKeyPair(
                new CertificateKeyPair(cert, new CustomECPrivateKey(tlsContext.getConfig()
                        .getDefaultClientEcPrivateKey(), tlsContext.getConfig().getDefaultSelectedNamedGroup())));
        tlsContext.getConfig().setAutoSelectCertificate(false);
        assertArrayEquals(ArrayConverter.concatenate(tlsContext.getClientRandom(), tlsContext.getServerRandom()), msg
                .getComputations().getClientServerRandom().getValue());
        assertEquals(EllipticCurveType.NAMED_CURVE, EllipticCurveType.getCurveType(msg.getGroupType().getValue()));
        assertArrayEquals(NamedGroup.SECP384R1.getValue(), msg.getNamedGroup().getValue());
        String serializedPubKeyExcpected = "04C93A166226760CD96FE96276AEF24A2C43E2AD8F71753662E11406D7F06A0684EDCAAD3296B6738DBA308EEAFA2EA7A4E5185E7819DE1F499A422F0293CD490D6946373842900228DAFAE3C965BB15D8EAA880EABA0B4881D81A82FA88A16310";
        assertEquals(serializedPubKeyExcpected, ArrayConverter.bytesToRawHexString(msg.getPublicKey().getValue()));
        assertArrayEquals(ArrayConverter.hexStringToByteArray("0601"), msg.getSignatureAndHashAlgorithm().getValue());
        String sigExpected = "4E2926B855813523BCF19289E39ADEC4F1A3A4B6706723A3C20EA1A677AAC4705ED20D6AEA6E9A875182D5D89A03F34B8814BB1BE0DE564B5B82A4F97B63594ADDD9E86A1CD06A2BBC046DC8AA89B0434862540567ADDE31C2ADDDAECE3A9C95E8B222D8F9E1348BC753C0184143585BEFA6C463FC43E033A25657BB15FF1CF8";
        assertEquals(128, (long) msg.getSignatureLength().getValue());
        assertEquals(sigExpected, ArrayConverter.bytesToRawHexString(msg.getSignature().getValue()));
    }

    private void loadTestVectorsToContext() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
            CertificateException, KeyStoreException, UnrecoverableKeyException {

        tlsContext.setConnection(new InboundConnection());

        Config config = tlsContext.getConfig();
        config.setDefaultServerRSAModulus(new BigInteger(
                "138176188281796802921728019830883835791466819775862616369528695291051113778191409365728255919237920070170415489798919694047238160141762618463534095589006064306561457254708835463402335256295540403269922932223802187003458396441731541262280889819064536522708759209693618435045828861540756050456047286072194938393"));
        config.setDefaultServerRSAPublicKey(new BigInteger("65537"));
        config.setDefaultServerRSAPrivateKey(new BigInteger(
                "14412811436201885114865385104046903298449229900480596388331753986444686418171665996675440704699794339070829612101033233570455163689657586703949205448013264184348068987367675661812419501134437771698938168350748107551389943071416238444845593800428715108981594372030316329952869373604711395976776700362569716737"));

        String clientRandom = "F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2";
        String serverRandom = "2323232323232323232323232323232323232323232323232323232323232323";

        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setClientRandom(ArrayConverter.hexStringToByteArray(clientRandom));
        tlsContext.setServerRandom(ArrayConverter.hexStringToByteArray(serverRandom));
        tlsContext.getConfig().setDefaultSelectedNamedGroup(NamedGroup.SECP384R1);

        List<NamedGroup> clientCurves = new ArrayList<>();
        clientCurves.add(NamedGroup.SECP384R1);
        List<NamedGroup> serverCurves = new ArrayList<>();
        serverCurves.add(NamedGroup.BRAINPOOLP256R1);
        serverCurves.add(NamedGroup.SECP384R1);
        serverCurves.add(NamedGroup.SECP256R1);
        tlsContext.setClientNamedGroupsList(clientCurves);
        config.setDefaultServerNamedGroups(serverCurves);
        config.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA512);
        List<ECPointFormat> clientFormats = new ArrayList<>();
        clientFormats.add(ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        clientFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        clientFormats.add(ECPointFormat.UNCOMPRESSED);
        List<ECPointFormat> serverFormats = new ArrayList<>();
        serverFormats.add(ECPointFormat.UNCOMPRESSED);
        tlsContext.setClientPointFormatsList(clientFormats);
        config.setDefaultServerSupportedPointFormats(serverFormats);

        List<SignatureAndHashAlgorithm> SigAndHashList = new LinkedList<>();
        SigAndHashList.add(SignatureAndHashAlgorithm.RSA_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(SigAndHashList);
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
