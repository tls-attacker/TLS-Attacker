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
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ServerConnectionEnd;
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
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
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
    public void testPrepareHandshakeMessageContents() {
        preparator.prepareHandshakeMessageContents();
        tlsContext
                .getConfig()
                .setDefaultRsaCertificate(
                        ArrayConverter
                                .hexStringToByteArray("3082024E308201B7A003020102020900A85273EFE099F4E5300D06092A864886F70D01010B05003040310B3009060355040613024445310C300A06035504080C034E5257310F300D06035504070C06426F6368756D3112301006035504030C093132372E302E302E31301E170D3137303530393037303130345A170D3237303530373037303130345A3040310B3009060355040613024445310C300A06035504080C034E5257310F300D06035504070C06426F6368756D3112301006035504030C093132372E302E302E3130819F300D06092A864886F70D010101050003818D0030818902818100C4C4F8F259F5AC2016120A7663E406D8C1C37FCBD02638E65A57E4D986ABB48098A926A45C9195269C21A89207F8DB5972564008D03D66B8A061A04E0B9434A77C42601F43A35466D384D82A83342F07CABBF3B29AB638EF35CF547CEEC3ADD729145DA7166E13BF3A0AA71D77B5E73942F6F100C91E8D38FF9D27D05960B6190203010001A350304E301D0603551D0E041604148349ED34A2AA0DFC769249FCA4E5E65D95323E6C301F0603551D230418301680148349ED34A2AA0DFC769249FCA4E5E65D95323E6C300C0603551D13040530030101FF300D06092A864886F70D01010B050003818100B01CD6269DB8D68A79FEB487D26FF7E24CA8F09F7B3536A5F1E4F4B45B2DD5C65342D4943AF1FE7B9390A225BE472487235604EE1FF2624A20F741CF515EF526164649D64B9A6E9027D48CBD2AD692F407D026711099A798C1E888886D24E3698FA553F4A1222D64C0E346430C585953DE42983FE6A35D9482DB6EF6798AC875"));

        assertArrayEquals(tlsContext.getClientRandom(), msg.getComputations().getClientRandom().getValue());
        assertArrayEquals(tlsContext.getServerRandom(), msg.getComputations().getServerRandom().getValue());

        assertEquals(EllipticCurveType.NAMED_CURVE, EllipticCurveType.getCurveType(msg.getCurveType().getValue()));
        assertArrayEquals(NamedCurve.SECP384R1.getValue(), msg.getNamedCurve().getValue());

        String serializedPubKeyExcpected = "0453E2F98C7D459354029E08404C690D857F921CE4A6AA71C2F114D04D24E033E08CFB5C9B84FA81DB3FB5CA35639AE69BDDC3E657ACD0532EF9C100F0863D9A3145BABBFDD727491991FBDD377C4EEBAE2D5ADDF3C8152824C9B4442E628A8CF3";
        assertEquals(serializedPubKeyExcpected, ArrayConverter.bytesToRawHexString(msg.getPublicKey().getValue()));

        assertArrayEquals(ArrayConverter.hexStringToByteArray("0601"), msg.getSignatureAndHashAlgorithm().getValue());

        String sigExpected = "543E5CC620CE4CD46062CADAB5DF7FF2A64D61D7D78C8D3D7BC1843406050FF54AA8D8BF60A1FF4CE77E499C0520CD2B697F01E1BCF19EF0E0E242B8FC374184A2C26DE227036C9E6852E3FEE3A4281B6B8CD43760D07B611A9FF45D0DD5EA81ABEF2F11173F58B6E088045A759E7D2AAAE6AF44A5CFDB1A7B3EA8C1DE229840";
        assertEquals(128, (int) msg.getSignatureLength().getValue());
        assertEquals(sigExpected, ArrayConverter.bytesToRawHexString(msg.getSignature().getValue()));

    }

    private void loadTestVectorsToContext() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
            CertificateException, KeyStoreException, UnrecoverableKeyException {

        tlsContext.setConnectionEnd(new ServerConnectionEnd());

        Config config = tlsContext.getConfig();
        config.setDefaultRSAModulus(new BigInteger(
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

        List<NamedCurve> clientCurves = new ArrayList<>();
        clientCurves.add(NamedCurve.SECP384R1);
        List<NamedCurve> serverCurves = new ArrayList<>();
        serverCurves.add(NamedCurve.BRAINPOOLP256R1);
        serverCurves.add(NamedCurve.SECP384R1);
        serverCurves.add(NamedCurve.SECP256R1);
        tlsContext.setClientNamedCurvesList(clientCurves);
        config.setNamedCurves(serverCurves);
        config.setDefaultSelectedSignatureAndHashAlgorithm(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA,
                HashAlgorithm.SHA512));
        List<ECPointFormat> clientFormats = new ArrayList<>();
        clientFormats.add(ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        clientFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        clientFormats.add(ECPointFormat.UNCOMPRESSED);
        List<ECPointFormat> serverFormats = new ArrayList<>();
        serverFormats.add(ECPointFormat.UNCOMPRESSED);
        tlsContext.setClientPointFormatsList(clientFormats);
        config.setDefaultServerSupportedPointFormats(serverFormats);

        List<SignatureAndHashAlgorithm> SigAndHashList = new LinkedList<>();
        SigAndHashList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512));
        config.setSupportedSignatureAndHashAlgorithms(SigAndHashList);
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
