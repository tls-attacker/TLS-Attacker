/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.*;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RecordDecryptorTest {

    private RecordCipher recordCipher;
    private TlsContext context;
    private Record record;
    public RecordDecryptor decryptor;

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        context = new TlsContext();
        record = new Record();
        record.setContentType(ProtocolMessageType.HANDSHAKE.getValue());
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
    }

    @Test
    public void testDecryptTLS12Block() throws CryptoException, NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "131627113d23f777e8213670e029eec8756e5647680ec07941225b439b141b182a0c9933d7d15325e3ef08f5cb303ca1"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "6d7a0d859e1066056592e50ad856af84ffbc92a27d918a07422ec735ca9c4612"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "9c6f8ad46b0245426d583999550192e982d339144c1b6bbfa672c4374e3e4b31"));
        context.setConnection(new InboundConnection());
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        "04cc7a7f777567ccda7d45233d8180929b89dc55a67d8a5783b229610756b9cd0b5d7b96b7b533da0e5f21634b170c6561fc649c007bf5b02398eec7d6b68a55"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0CFA0129A250B604B2835881C24E3539"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("04cc7a7f777567ccda7d45233d818092"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1400000C0F10DC614D5CF06560FCA887"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("B1CF94C307D377CCC79E30A9EA46DF7F9ED48870"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "1400000C0F10DC614D5CF06560FCA887B1CF94C307D377CCC79E30A9EA46DF7F9ED488700B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS12Camellia() throws NoSuchAlgorithmException, CryptoException {
        context.setRandom(
                new TestRandomData(
                        ArrayConverter.hexStringToByteArray(
                                "16B406CF7A489CA985883AEDA28D34E34ED3256F1B380C692B962DF892180C5A")));
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "EC28993D8B3F3D81D626C3B419C34547373C5EA49C4A727790C59892AACFF4FEF0945725996013C65581110889D019DE"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "DA5BA97EAC47D864C1041B542885F0CD20F05F7F3E0929FBE38D2A72497D5A53"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "2488DFEE45765EEF369F30AFE356B9463624C6D617503AAB6B592B8CBDB55AB2"));
        context.setConnection(new InboundConnection());

        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        "16B406CF7A489CA985883AEDA28D34E3AB1B66A1C376C1F354607CFDA1739D9B60D30776152207B1988604FBCF75E6BC370ADE1EE684CAE9B0801AAE50CC2EFA"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("16B406CF7A489CA985883AEDA28D34E3"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("27BE1FB155ACFBF9E78D0C259E693123"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("11EBB8BC910709D40FA3612679F0CE5DB12575FD"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "27BE1FB155ACFBF9E78D0C259E69312311EBB8BC910709D40FA3612679F0CE5DB12575FD0B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS12Stream() throws CryptoException, NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "69a9fb0d9ee8e84ad7fd2b3f580d0ca99290d9cc9f6fe725f5baf12c732c1f3ea2ba7eec402313bb532428a5527f248b"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "3e01231046d4b84aef9b300616d971130abf22d04cbc665c2895a5fe0f99bdad"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "f0284f8ca99f6c0e7344a339ec30707b74d3a4bc94bddc48169e132dbe5f05fd"));
        context.setConnection(new InboundConnection());

        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        "2142ec1d8a2b0bff9866bd07682a3c1b3e1a6cd253763586edc5849bf53d17037f2578cf"));

        recordCipher =
                new RecordStreamCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1400000C8B8D449BFDE419B122162DF7"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("9E12D9D0FED1B0D456F3D7D612F1709CE7748B6F"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("799A4D36AA96F5E889D445F50BB59873"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1221BB2E19D8C955A3B78FF8C8F2EE9DA6CC4F71"),
                record.getComputations().getMacKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "1400000C8B8D449BFDE419B122162DF79E12D9D0FED1B0D456F3D7D612F1709CE7748B6F"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS12AEAD() throws CryptoException, NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);

        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "1D7565701019745C4546DD1A5D680EDCD0B9E0143ADAD741F111454DF6D4F77E9CFBA09473AFF84B4AFBB6D3782CD9B5"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "7ADDFA2D9C0560EC4B24018368600A1C100FFE5276F66A4802408CE94CD9DC07"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "30652D7EE1E67E5D716E713BB70059172EE36FA621DEBFC3444F574E47524401"));
        context.setConnection(new InboundConnection());
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        "A26A2D97CE709B530E53BF60E39AE84D58A167C2431ACF356B9C674265A14BAA6DBDF4BAFEF87F5F"));

        recordCipher =
                new RecordAEADCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getAuthenticationTagValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("90D7D8A9379E3186015E7B71BEEF7E3E"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("55AF867D"),
                record.getComputations().getAeadSalt().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("A26A2D97CE709B53"),
                record.getComputations().getExplicitNonce().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0E53BF60E39AE84D58A167C2431ACF35"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1400000CC5EC1A1363D0E7063263E1C2"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS10Block() throws CryptoException, NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);

        record.setCleanProtocolMessageBytes(ArrayConverter.hexStringToByteArray("080000020000"));
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "a079dee527fb963d65ae25bd7c919e4fac999ddbcfd46fe485f6138d6804d4688119c438132e651f2c82ab067378b162"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "51d994112bf1be7def9219a995a94cee7149e2a2ed3e19ef65994f912d66eb03"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "8ecf60fd3eb104aab5c72068742c29989f62fb7d84c7af41a7a8c0c39be21d34"));

        context.setConnection(new InboundConnection());
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        "1d42081019ffbdedc5e155e1dc3faab3e522bc764a2f476a57246bf59fc37f68463023f27e7f0fb64488ced496048124"));
        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1400000C679DC5EB7BD2A0DAA4202C59"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603010010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("CC3617A0335CFB03734BF8AA0F69F1EB"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("5E64EE204833E7738BA4FD1CCF57317E"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("80F1C23DC0ADF6E1773AB9ADF6E56E77CCD071F1"),
                record.getComputations().getMacKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "1400000C679DC5EB7BD2A0DAA4202C59F5AB5EC0FFCBBAF831A25B8FD4C8B2965CBB528F0B0B0B0B0B0B0B0B0B0B0B0B"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS10Stream() throws CryptoException, NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        context.setMasterSecret(ArrayConverter.hexStringToByteArray(""));

        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "01d5e27d3c693b7bfe22556f796c4151f4c498df292fa8e3c13e55d93ac41ca12806a1c5805d3007d0476af437b0f3da"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "1e909eeac8422512c4e74709179c515a6c58b313ead5e13e5dd1301a83e3b1d7"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "c3eafafa8b06600aa0b93e75abf84785b207610fbf29bf33e732e149970c15eb"));
        context.setConnection(new InboundConnection());

        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        "c98ff632fb3abf9f584c81dd196ecb38ea79383741c481b932022bee2bb3473792ad38a1"));

        recordCipher =
                new RecordStreamCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1400000C5063356364F28B8EA8BB349C"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603010010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("D14B2533E07B6691A902E7A9122D70990D055A90"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("98220F1634C791C674860E689D419227"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("08AE37FFE3A199DC060E07E92034D0A5CEB75BDC"),
                record.getComputations().getMacKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "1400000C5063356364F28B8EA8BB349CD14B2533E07B6691A902E7A9122D70990D055A90"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS12BlockEncryptThenMac()
            throws CryptoException, NoSuchAlgorithmException {

        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "A3B2E520EB4D835FE65420BBF1D0B40BDDBCF736E1E4D039818B8D2C0771A0C74B65DE06053BE942A12D6D5FD03F1F63"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "F2A7717805D27A704365ED11799FE1BB96F3C268A8DABDEBEB0AE7678EF89A4C"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "34E24F708AE545760E2137C746ECA02C3C706F22AA837A06BECB14CB04D0C016"));

        context.setConnection(new InboundConnection());
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        "09FF0714A189621595B6D0FB3F478E0AFD3BE7A6F40688505483433AAF6748EE634F8F837976DAFB8BAEDC2355298FC0D6B9D3CC28AD37E3FEAA4E533AF5375839C3866D"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "09FF0714A189621595B6D0FB3F478E0AFD3BE7A6F40688505483433AAF6748EE634F8F837976DAFB8BAEDC2355298FC0"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("09FF0714A189621595B6D0FB3F478E0A"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("04D9CB8C3ABCA4954295AF7F2E6FC3F4"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603030030"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "09FF0714A189621595B6D0FB3F478E0AFD3BE7A6F40688505483433AAF6748EE634F8F837976DAFB8BAEDC2355298FC0"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("D6B9D3CC28AD37E3FEAA4E533AF5375839C3866D"),
                record.getComputations().getMac().getValue());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "1400000CFEAD2DFC053F6FF99BA22C5C0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS13AEADStream() throws CryptoException, NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        context.setClientHandshakeTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "9ee198e67ea9cf1621a3cec7afce9d83303fcda210c8fbbb286c179bf7be1cab"));
        context.setServerHandshakeTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "d5caf18dcc2f06c57d5469dd0b46efaa03d674424c04cad6492397b99e43486b"));
        context.setClientApplicationTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "5c51d7e6640a1c54db17fbf797c9e82d7c2cba33b7dad1f6db74f5de8a82b9e0"));
        context.setServerApplicationTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "e257bd1e4cd2623144b37eca9cdd94f098868027ad7cb9bffa441e825b1fcd9c"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "41b133e84bd3d20207af00f9c72c05c74e0c75e1001ea02a270a52b7ab11f1f6"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "f31868408aa947f68121c093fb43ad5159a1dd40dafd9ece6b98ac64cf65eefe"));

        context.setConnection(new InboundConnection());
        context.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        context.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);

        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        record.setLength(0x35);
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        "2d2b71ffcdefbe88cfbc16973f2c3ef8f1e754dcd75712b4e0e2d2ce4bf58a8c55c1af006943cd3ab7c837c2d55331bee9ad9fd143"));

        recordCipher =
                new RecordAEADCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        // Testing the Authtag/Mac would be nice here but there is currently no
        // way of knowing if the mac computation has failed.
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(""),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "2D2B71FFCDEFBE88CFBC16973F2C3EF8F1E754DCD75712B4E0E2D2CE4BF58A8C55C1AF0069"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1703030035"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "C65B0E20F167F282E68DCE9BCDDB951FA3F8123EF93BF2DBA23B35031C273B93"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("C3089A2EADAAC0D9BB8564EC"),
                record.getComputations().getGcmNonce().getValue());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "14000020a7a0c5d20549e6deb7b1dff6e429dc0875b3ef55d328448385aaa182cc986ef316"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS13AEADBlock() throws CryptoException, NoSuchAlgorithmException {
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_256_GCM_SHA384);
        context.setClientHandshakeTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "e19c1c1e5761eff589d41b8009fc7fe52b9a2ac0fa93f07e4b7091f79c9ce9f992d0a3b7f6f121dfd6ce2539a7e2fb0f"));
        context.setServerHandshakeTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "ae2f018826cad84d086e93bd4ba8b6205864a676e312545b9cf255d51ca8c7ed70a128fcefe510bf3830cb984e6cbc7b"));
        context.setClientApplicationTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "b12a8280f7a499a61a721361adbd3e560f719fd5b179c4346e88f99d2068bab9f76cb5ae89354fbdd02331b6685d5e81"));
        context.setServerApplicationTrafficSecret(
                ArrayConverter.hexStringToByteArray(
                        "c5233161c3e98ca9adb6799572e1288663966c0b72ef3a0c17220b576edcd0adba2f6da483a1c63a1fe76a5d486826c4"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "220d0cb249adf771399d92f2d4b45b109658b1a600b9bc1ad7f54f3d6f00547c"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "f443fd3d638b94a0ecb0cf432860969967fde9a86693522120e33695a29dc4f3"));

        context.setConnection(new InboundConnection());
        context.setActiveClientKeySetType(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);
        context.setActiveServerKeySetType(Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS);

        record.setContentMessageType(ProtocolMessageType.APPLICATION_DATA);
        record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());

        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray("619f8c33dc44e80a7399ff70e10af19466be2085cf"));
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        recordCipher =
                new RecordAEADCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeySetGenerator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(""),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("1703030015"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("619F8C33DC"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("44e80a7399ff70e10af19466be2085cf"),
                record.getComputations().getAuthenticationTag().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "af954245169b81e3da5bec540e4e2c48d1af0aa93b4fcc3fa1607075d0db70b4"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("9e7ef2bc05c19ebc2a90e600"),
                record.getComputations().getGcmNonce().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("6173640a17"),
                record.getComputations().getPlainRecordBytes().getValue());
    }
}
