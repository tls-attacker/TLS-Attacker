/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.BadFixedRandom;
import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ECDHEServerKeyExchangePreparatorTest
        extends AbstractProtocolMessagePreparatorTest<
                ECDHEServerKeyExchangeMessage,
                ECDHEServerKeyExchangePreparator<ECDHEServerKeyExchangeMessage>> {

    @BeforeEach
    public void before() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public ECDHEServerKeyExchangePreparatorTest() {
        super(ECDHEServerKeyExchangeMessage::new, ECDHEServerKeyExchangePreparator::new);
        BadFixedRandom rnd = new BadFixedRandom((byte) 0x23);
        BadRandom random = new BadRandom(rnd, null);
        context.getConfig()
                .setDefaultServerEphemeralEcPrivateKey(
                        new BigInteger(
                                "191991257030464195512760799659436374116556484140110877679395918219072292938297573720808302564562486757422301181089761"));
        loadTestVectorsToContext();
        context.setRandom(random);
    }

    @Test
    @Override
    public void testPrepare() throws IOException {
        preparator.prepareHandshakeMessageContents();
        assertArrayEquals(
                ArrayConverter.concatenate(context.getClientRandom(), context.getServerRandom()),
                message.getKeyExchangeComputations().getClientServerRandom().getValue());
        assertEquals(
                EllipticCurveType.NAMED_CURVE,
                EllipticCurveType.getCurveType(message.getGroupType().getValue()));
        assertArrayEquals(NamedGroup.SECP384R1.getValue(), message.getNamedGroup().getValue());
        String serializedPubKeyExpected =
                "04C93A166226760CD96FE96276AEF24A2C43E2AD8F71753662E11406D7F06A0684EDCAAD3296B6738DBA308EEAFA2EA7A4E5185E7819DE1F499A422F0293CD490D6946373842900228DAFAE3C965BB15D8EAA880EABA0B4881D81A82FA88A16310";
        assertEquals(
                serializedPubKeyExpected,
                ArrayConverter.bytesToRawHexString(message.getPublicKey().getValue()));
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0601"),
                message.getSignatureAndHashAlgorithm().getValue());
        String sigExpected =
                "4E2926B855813523BCF19289E39ADEC4F1A3A4B6706723A3C20EA1A677AAC4705ED20D6AEA6E9A875182D5D89A03F34B8814BB1BE0DE564B5B82A4F97B63594ADDD9E86A1CD06A2BBC046DC8AA89B0434862540567ADDE31C2ADDDAECE3A9C95E8B222D8F9E1348BC753C0184143585BEFA6C463FC43E033A25657BB15FF1CF8";
        assertEquals(128, (long) message.getSignatureLength().getValue());
        assertEquals(
                sigExpected, ArrayConverter.bytesToRawHexString(message.getSignature().getValue()));
    }

    private void loadTestVectorsToContext() {
        Config config = new Config();
        context.setConnection(new InboundConnection());

        context.getX509Context()
                .setSubjectRsaModulus(
                        new BigInteger(
                                "138176188281796802921728019830883835791466819775862616369528695291051113778191409365728255919237920070170415489798919694047238160141762618463534095589006064306561457254708835463402335256295540403269922932223802187003458396441731541262280889819064536522708759209693618435045828861540756050456047286072194938393"));
        context.getX509Context().setSubjectRsaPublicExponent(new BigInteger("65537"));
        context.getX509Context()
                .setSubjectRsaPrivateKey(
                        new BigInteger(
                                "14412811436201885114865385104046903298449229900480596388331753986444686418171665996675440704699794339070829612101033233570455163689657586703949205448013264184348068987367675661812419501134437771698938168350748107551389943071416238444845593800428715108981594372030316329952869373604711395976776700362569716737"));

        String clientRandom = "F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2";
        String serverRandom = "2323232323232323232323232323232323232323232323232323232323232323";

        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter.hexStringToByteArray(clientRandom));
        context.setServerRandom(ArrayConverter.hexStringToByteArray(serverRandom));
        context.getConfig().setDefaultSelectedNamedGroup(NamedGroup.SECP384R1);

        List<NamedGroup> clientCurves = new ArrayList<>();
        clientCurves.add(NamedGroup.SECP384R1);
        List<NamedGroup> serverCurves = new ArrayList<>();
        serverCurves.add(NamedGroup.BRAINPOOLP256R1);
        serverCurves.add(NamedGroup.SECP384R1);
        serverCurves.add(NamedGroup.SECP256R1);
        context.setClientNamedGroupsList(clientCurves);
        config.setDefaultServerNamedGroups(serverCurves);
        config.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA512);
        List<ECPointFormat> clientFormats = new ArrayList<>();
        clientFormats.add(ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        clientFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        clientFormats.add(ECPointFormat.UNCOMPRESSED);
        List<ECPointFormat> serverFormats = new ArrayList<>();
        serverFormats.add(ECPointFormat.UNCOMPRESSED);
        context.setClientPointFormatsList(clientFormats);
        config.setDefaultServerSupportedPointFormats(serverFormats);

        List<SignatureAndHashAlgorithm> SigAndHashList = new LinkedList<>();
        SigAndHashList.add(SignatureAndHashAlgorithm.RSA_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(SigAndHashList);
    }
}
