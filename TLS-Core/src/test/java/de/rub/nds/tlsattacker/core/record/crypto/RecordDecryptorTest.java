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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordStreamCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeyDerivator;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.util.test.TestRandomData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RecordDecryptorTest {

    private RecordCipher recordCipher;
    private TlsContext context;
    private Record record;
    public RecordDecryptor decryptor;

    @BeforeEach
    public void setUp() {
        context = new Context(new State(new Config()), new InboundConnection()).getTlsContext();
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
                                KeyDerivator.generateKeySet(context),
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
                                KeyDerivator.generateKeySet(context),
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
                                KeyDerivator.generateKeySet(context),
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
                                KeyDerivator.generateKeySet(context),
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
                                KeyDerivator.generateKeySet(context),
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
                                KeyDerivator.generateKeySet(context),
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
                                KeyDerivator.generateKeySet(context),
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
                                KeyDerivator.generateKeySet(context),
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
                                KeyDerivator.generateKeySet(context),
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

    @Test
    public void testDecryptTLS12WithNegativePaddingEncryptThenMac()
            throws CryptoException, NoSuchAlgorithmException {

        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "eeb18d0e03fcd9dcfc3432be940d26f9efe76f8340fb411f3e91b5be4f15e7cf1744d04062b43a074beecee5a01e300d"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "998e5dbcd360df728cf0d92a4fd9aff782958dbd7dd1c16c9e16d3cae4e88c13"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "3ff48b72d311505a8f7184920b56c09a7cda74169209e4bde55491c7ff81b7a5"));

        context.setConnection(new InboundConnection());
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        // random 16 bytes IV + CTXT (padding is here) + MAC
                        "d7a61d26aaed357ca508d4a6d3109b91"
                                + "4d2f2d45976c2421320b0a909e51b8cf4e9b073595caca646715a7dc09ff195e75ffe684ea10ebadd9b78996d2eec2209c8eca9697d871bee1ecc372bc2e8879ddde24364e7f35eab89e2964097963f9de066e8ae649e6dfcd218f3de0276eea622ec6fd527c835c47880a966b38d73922ff71a7a95c843ea846f5a7c4785e180c25fd759d9cbdebca14cd921c743d5eb8910f618db2dc7ce2a57f80e57d4fb8327da198bf65e25a7932a61c74015b172ff4939c2a99eefd0205f4940b77b9d07daac9c13cf3cc5f8ca6bea7b220db7cd42eb20b2fa51a816f86407033574471b38b2c2cf029deb75215d8af27b9b94899a18aa029047c50d8ebb30afebe1268e7cd349fc079a2e270221de329023ff1"
                                + "280abf484813cd3dae4206c32a3d3f1604f72f83"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeyDerivator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "d7a61d26aaed357ca508d4a6d3109b914d2f2d45976c2421320b0a909e51b8cf4e9b073595caca646715a7dc09ff195e75ffe684ea10ebadd9b78996d2eec2209c8eca9697d871bee1ecc372bc2e8879ddde24364e7f35eab89e2964097963f9de066e8ae649e6dfcd218f3de0276eea622ec6fd527c835c47880a966b38d73922ff71a7a95c843ea846f5a7c4785e180c25fd759d9cbdebca14cd921c743d5eb8910f618db2dc7ce2a57f80e57d4fb8327da198bf65e25a7932a61c74015b172ff4939c2a99eefd0205f4940b77b9d07daac9c13cf3cc5f8ca6bea7b220db7cd42eb20b2fa51a816f86407033574471b38b2c2cf029deb75215d8af27b9b94899a18aa029047c50d8ebb30afebe1268e7cd349fc079a2e270221de329023ff1"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("d7a61d26aaed357ca508d4a6d3109b91"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("7bcda020ab2c28df8fb4ebe4b61ac5cd"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603030120"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("280abf484813cd3dae4206c32a3d3f1604f72f83"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "48656c6c6f2c20576f726c6421313233ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS11WithNegativePaddingEncryptThenMac()
            throws CryptoException, NoSuchAlgorithmException {

        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "eeb18d0e03fcd9dcfc3432be940d26f9efe76f8340fb411f3e91b5be4f15e7cf1744d04062b43a074beecee5a01e300d"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "998e5dbcd360df728cf0d92a4fd9aff782958dbd7dd1c16c9e16d3cae4e88c13"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "3ff48b72d311505a8f7184920b56c09a7cda74169209e4bde55491c7ff81b7a5"));

        context.setConnection(new InboundConnection());
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        // random 16 bytes IV + CTXT (padding is here) + MAC
                        "d7a61d26aaed357ca508d4a6d3109b91"
                                + "cd3d4d40581d068228309a9776c69b0ba5c7a6073e756a4b8346f26f831960358dbf842e63eebe28efa769b7cc88fe5865735c265919656e5fa9bd1215b8b0b8eded6eda82328c2f560f72f1d3db68cb7f95b356239c5bd8bde8aa4a1ed59fd0fe2ae9009cf8ac518b1b03bc10f09b784d4890cda1721030fff65ec08c96b9389f34b51f097129c27bc848c182ba5022691684b6fca130a8fddb04ed93624466"
                                + "0b2f8d4310b7d5539e22f98a4b06f4bfcca210c1"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeyDerivator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "d7a61d26aaed357ca508d4a6d3109b91cd3d4d40581d068228309a9776c69b0ba5c7a6073e756a4b8346f26f831960358dbf842e63eebe28efa769b7cc88fe5865735c265919656e5fa9bd1215b8b0b8eded6eda82328c2f560f72f1d3db68cb7f95b356239c5bd8bde8aa4a1ed59fd0fe2ae9009cf8ac518b1b03bc10f09b784d4890cda1721030fff65ec08c96b9389f34b51f097129c27bc848c182ba5022691684b6fca130a8fddb04ed93624466"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("d7a61d26aaed357ca508d4a6d3109b91"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("fab239a4db25fb41d129439e660a8874"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("000000000000000016030200b0"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("0b2f8d4310b7d5539e22f98a4b06f4bfcca210c1"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "48656c6c6f2c20576f726c64213132338f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS10WithNegativePaddingEncryptThenMac()
            throws CryptoException, NoSuchAlgorithmException {

        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.addNegotiatedExtension(ExtensionType.ENCRYPT_THEN_MAC);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "eeb18d0e03fcd9dcfc3432be940d26f9efe76f8340fb411f3e91b5be4f15e7cf1744d04062b43a074beecee5a01e300d"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "998e5dbcd360df728cf0d92a4fd9aff782958dbd7dd1c16c9e16d3cae4e88c13"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "3ff48b72d311505a8f7184920b56c09a7cda74169209e4bde55491c7ff81b7a5"));

        context.setConnection(new InboundConnection());
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        // CTXT (padding is here) + MAC
                        "bd6f8e21c51c14a86f083caf537a9bf34954db3956064ecb6d128778177ed59296722cda6d5b765cf8427b16aa474ca1eb0a64a3df08f0ec1e09cfd5329cd3b2fa06b76d7bd50a88e97f6e83280839478cb1f667e977474fd85766cc41466c4d139325682e9086aa84299adb2bab9813db67da0b9b557087141e02beddf310f666f8b1cb7a38ff0919f3ed4cdb9e064cded98ad2a1ee1ae028997821e19a01d8"
                                + "b628598ec7ee611519ef0c9c5b179180529205bd"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeyDerivator.generateKeySet(context),
                                context.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "bd6f8e21c51c14a86f083caf537a9bf34954db3956064ecb6d128778177ed59296722cda6d5b765cf8427b16aa474ca1eb0a64a3df08f0ec1e09cfd5329cd3b2fa06b76d7bd50a88e97f6e83280839478cb1f667e977474fd85766cc41466c4d139325682e9086aa84299adb2bab9813db67da0b9b557087141e02beddf310f666f8b1cb7a38ff0919f3ed4cdb9e064cded98ad2a1ee1ae028997821e19a01d8"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("d2212014bcfcf767bb36cafeaa0dce3c"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("fab239a4db25fb41d129439e660a8874"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("000000000000000016030100a0"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("b628598ec7ee611519ef0c9c5b179180529205bd"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "48656c6c6f2c20576f726c64213132338f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS12WithNegativePaddingMacThenEncrypt()
            throws CryptoException, NoSuchAlgorithmException {

        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "eeb18d0e03fcd9dcfc3432be940d26f9efe76f8340fb411f3e91b5be4f15e7cf1744d04062b43a074beecee5a01e300d"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "998e5dbcd360df728cf0d92a4fd9aff782958dbd7dd1c16c9e16d3cae4e88c13"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "3ff48b72d311505a8f7184920b56c09a7cda74169209e4bde55491c7ff81b7a5"));

        context.setConnection(new InboundConnection());
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        // random 16 bytes IV + CTXT
                        "d7a61d26aaed357ca508d4a6d3109b91"
                                + "4d2f2d45976c2421320b0a909e51b8cf468bf98a0eed440c06f4570c3f5abf3695913073b002403cc5a7c60b041b8419d5266d88198454a97c7d369704c2eb9e8b3bfb573e332dc953b1480348e8719eeeaea46a67d8242ee9616206cdabe0c73fe7aafa8687acdf69b54bea1d664cd9f15a62bc2a07d5cace0fa622d5e3dd4f8978fa1a593d198d66a5c053a5b3473f02f8d04dbdc2195dcf8dc7261834619ff536bbccca49f464a1f2e34fc1e0c1f3"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeyDerivator.generateKeySet(context),
                                context.isExtensionNegotiated(null)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("48656c6c6f2c20576f726c6421313233"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("d7a61d26aaed357ca508d4a6d3109b91"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("7bcda020ab2c28df8fb4ebe4b61ac5cd"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603030010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("34d28c0f947f354bac42cf9969f4b7d1d026e997"),
                record.getComputations().getMac().getValue());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "48656c6c6f2c20576f726c642131323334d28c0f947f354bac42cf9969f4b7d1d026e9978b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS11WithNegativePaddingMacThenEncrypt()
            throws CryptoException, NoSuchAlgorithmException {

        context.setSelectedProtocolVersion(ProtocolVersion.TLS11);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "eeb18d0e03fcd9dcfc3432be940d26f9efe76f8340fb411f3e91b5be4f15e7cf1744d04062b43a074beecee5a01e300d"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "998e5dbcd360df728cf0d92a4fd9aff782958dbd7dd1c16c9e16d3cae4e88c13"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "3ff48b72d311505a8f7184920b56c09a7cda74169209e4bde55491c7ff81b7a5"));

        context.setConnection(new InboundConnection());
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS11.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        // random 16 bytes IV + CTXT
                        "d7a61d26aaed357ca508d4a6d3109b91"
                                + "cd3d4d40581d068228309a9776c69b0b53102970f187d015b5cdacb60e622c68a311390e8e4c5b9f68c0228afe59c646256ca576b21f10a00fb7a89b8b868f5f7324efe601420eed4168ef2f52fa296ea9c54c64e33d91120261a5e92a4eee6a738b3c2db7e1eb654967f365766780d2d828d2346cd2e0ed813e19ee1d7462d913e7e3589f8375fbe495bf62ce35acdbbf28f1b7ab3faa14ed0683f03835964e3a1c9c0c00b4bc2281542b81acc2e6d1"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeyDerivator.generateKeySet(context),
                                context.isExtensionNegotiated(null)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("48656c6c6f2c20576f726c6421313233"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("d7a61d26aaed357ca508d4a6d3109b91"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("fab239a4db25fb41d129439e660a8874"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603020010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("fbdf5aec0fd29c001a7013bce7302ba6ec0fec37"),
                record.getComputations().getMac().getValue());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "48656c6c6f2c20576f726c6421313233fbdf5aec0fd29c001a7013bce7302ba6ec0fec378b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"),
                record.getComputations().getPlainRecordBytes().getValue());
    }

    @Test
    public void testDecryptTLS10WithNegativePaddingMacThenEncrypt()
            throws CryptoException, NoSuchAlgorithmException {

        context.setSelectedProtocolVersion(ProtocolVersion.TLS10);
        context.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        context.setMasterSecret(
                ArrayConverter.hexStringToByteArray(
                        "eeb18d0e03fcd9dcfc3432be940d26f9efe76f8340fb411f3e91b5be4f15e7cf1744d04062b43a074beecee5a01e300d"));
        context.setClientRandom(
                ArrayConverter.hexStringToByteArray(
                        "998e5dbcd360df728cf0d92a4fd9aff782958dbd7dd1c16c9e16d3cae4e88c13"));
        context.setServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "3ff48b72d311505a8f7184920b56c09a7cda74169209e4bde55491c7ff81b7a5"));

        context.setConnection(new InboundConnection());
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setProtocolVersion(ProtocolVersion.TLS10.getValue());
        record.setProtocolMessageBytes(
                ArrayConverter.hexStringToByteArray(
                        // CTXT
                        "bd6f8e21c51c14a86f083caf537a9bf342bd2aa2c31aa8be6806006c6320f1e45a11d82b710e444308e85d14cf1c67ece7762965aa1c295edf128426dd7cc05a21ce11e65cdebe7bd5ad7b51acd83a90d0a5b0f13a86b212f12910870362f5b8554bff1167793db72d685cd49604751f33aa917ad2616918c5f235001bd31ee8c402e9d2358f6bfd15b48e0b66d8ccf09bad3811c8bfc24cb78b216a760c80846442a864e1e3ca6a2c8b5ee23aa241a5"));

        recordCipher =
                new RecordBlockCipher(
                        context,
                        new CipherState(
                                context.getChooser().getSelectedProtocolVersion(),
                                context.getChooser().getSelectedCipherSuite(),
                                KeyDerivator.generateKeySet(context),
                                context.isExtensionNegotiated(null)));
        decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertTrue(record.getComputations().getMacValid());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("48656c6c6f2c20576f726c6421313233"),
                record.getComputations().getAuthenticatedNonMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("d2212014bcfcf767bb36cafeaa0dce3c"),
                record.getComputations().getCbcInitialisationVector().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("fab239a4db25fb41d129439e660a8874"),
                record.getComputations().getCipherKey().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"),
                record.getComputations().getPadding().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("00000000000000001603010010"),
                record.getComputations().getAuthenticatedMetaData().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray("23de3ef8eac88e84e2474740f0467a63cf0ff600"),
                record.getComputations().getMac().getValue());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "48656c6c6f2c20576f726c642131323323de3ef8eac88e84e2474740f0467a63cf0ff6008b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"),
                record.getComputations().getPlainRecordBytes().getValue());
    }
}
