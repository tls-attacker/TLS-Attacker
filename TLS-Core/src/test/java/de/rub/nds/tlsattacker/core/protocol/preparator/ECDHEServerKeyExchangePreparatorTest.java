/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import java.util.List;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.modifiablevariable.util.BadFixedRandom;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToRawHexString;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.unittest.helper.TestCertificates;
import static de.rub.nds.tlsattacker.core.util.JKSLoader.loadTLSCertificate;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import static de.rub.nds.tlsattacker.core.unittest.helper.TestCertificates.keyPairFromStore;
import static de.rub.nds.tlsattacker.core.unittest.helper.TestCertificates.keyStoreFromRsaPem;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 * 
 */
public class ECDHEServerKeyExchangePreparatorTest {

    private TlsContext ctx;
    private SecureRandom rndHelper;
    ECDHEServerKeyExchangeMessage msg;
    ECDHEServerKeyExchangePreparator preparator;

    public ECDHEServerKeyExchangePreparatorTest() {
    }

    @Before
    public void setUp() throws IOException {
        this.ctx = new TlsContext();

        BadFixedRandom rnd = new BadFixedRandom((byte) 0x23);
        rndHelper = new BadRandom(rnd, null);

        try {
            loadTestVectorsToContext();
        } catch (IOException ex) {
            throw new IOException("Failed to set up test context", ex);
        }
    }

    @Before
    public void freshPreparator() {
        msg = new ECDHEServerKeyExchangeMessage();
        preparator = new ECDHEServerKeyExchangePreparator(ctx, msg);
        preparator.setRandomHelper(rndHelper);
        preparator.prepareHandshakeMessageContents();
    }

    @Test
    public void testPrepareHandshakeMessageContents() {

        byte[] cert = null;
        try {
            cert = ctx.getConfig().getOurCertificate().getCertificateAt(0).getEncoded();
        } catch (IOException ex) {
            Logger.getLogger(ECDHEServerKeyExchangePreparatorTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        String certExpected = "3082024E308201B7A003020102020900A85273EFE099F4E5300D06092A864886F70D01010B05003040310B3009060355040613024445310C300A06035504080C034E5257310F300D06035504070C06426F6368756D3112301006035504030C093132372E302E302E31301E170D3137303530393037303130345A170D3237303530373037303130345A3040310B3009060355040613024445310C300A06035504080C034E5257310F300D06035504070C06426F6368756D3112301006035504030C093132372E302E302E3130819F300D06092A864886F70D010101050003818D0030818902818100C4C4F8F259F5AC2016120A7663E406D8C1C37FCBD02638E65A57E4D986ABB48098A926A45C9195269C21A89207F8DB5972564008D03D66B8A061A04E0B9434A77C42601F43A35466D384D82A83342F07CABBF3B29AB638EF35CF547CEEC3ADD729145DA7166E13BF3A0AA71D77B5E73942F6F100C91E8D38FF9D27D05960B6190203010001A350304E301D0603551D0E041604148349ED34A2AA0DFC769249FCA4E5E65D95323E6C301F0603551D230418301680148349ED34A2AA0DFC769249FCA4E5E65D95323E6C300C0603551D13040530030101FF300D06092A864886F70D01010B050003818100B01CD6269DB8D68A79FEB487D26FF7E24CA8F09F7B3536A5F1E4F4B45B2DD5C65342D4943AF1FE7B9390A225BE472487235604EE1FF2624A20F741CF515EF526164649D64B9A6E9027D48CBD2AD692F407D026711099A798C1E888886D24E3698FA553F4A1222D64C0E346430C585953DE42983FE6A35D9482DB6EF6798AC875";
        assertEquals(certExpected, bytesToRawHexString(cert));

        assertArrayEquals(ctx.getClientRandom(), msg.getComputations().getClientRandom().getValue());
        assertArrayEquals(ctx.getServerRandom(), msg.getComputations().getServerRandom().getValue());

        assertEquals(EllipticCurveType.NAMED_CURVE, EllipticCurveType.getCurveType(msg.getCurveType().getValue()));
        assertArrayEquals(NamedCurve.SECP384R1.getValue(), msg.getNamedCurve().getValue());

        String serializedPubKeyExcpected = "0453E2F98C7D459354029E08404C690D857F921CE4A6AA71C2F114D04D24E033E08CFB5C9B84FA81DB3FB5CA35639AE69BDDC3E657ACD0532EF9C100F0863D9A3145BABBFDD727491991FBDD377C4EEBAE2D5ADDF3C8152824C9B4442E628A8CF3";
        assertEquals(serializedPubKeyExcpected, bytesToRawHexString(msg.getSerializedPublicKey().getValue()));

        assertTrue(SignatureAlgorithm.RSA.getValue() == msg.getSignatureAlgorithm().getValue());
        assertTrue(HashAlgorithm.SHA512.getValue() == msg.getHashAlgorithm().getValue());

        String sigExpected = "543E5CC620CE4CD46062CADAB5DF7FF2A64D61D7D78C8D3D7BC1843406050FF54AA8D8BF60A1FF4CE77E499C0520CD2B697F01E1BCF19EF0E0E242B8FC374184A2C26DE227036C9E6852E3FEE3A4281B6B8CD43760D07B611A9FF45D0DD5EA81ABEF2F11173F58B6E088045A759E7D2AAAE6AF44A5CFDB1A7B3EA8C1DE229840";
        assertEquals(new Integer(128), msg.getSignatureLength().getValue());
        assertEquals(sigExpected, bytesToRawHexString(msg.getSignature().getValue()));

    }

    private void loadTestVectorsToContext() throws IOException {

        TlsConfig config = ctx.getConfig();

        String cert = "-----BEGIN CERTIFICATE-----\n"
                + "MIICTjCCAbegAwIBAgIJAKhSc+/gmfTlMA0GCSqGSIb3DQEBCwUAMEAxCzAJBgNV\n"
                + "BAYTAkRFMQwwCgYDVQQIDANOUlcxDzANBgNVBAcMBkJvY2h1bTESMBAGA1UEAwwJ\n"
                + "MTI3LjAuMC4xMB4XDTE3MDUwOTA3MDEwNFoXDTI3MDUwNzA3MDEwNFowQDELMAkG\n"
                + "A1UEBhMCREUxDDAKBgNVBAgMA05SVzEPMA0GA1UEBwwGQm9jaHVtMRIwEAYDVQQD\n"
                + "DAkxMjcuMC4wLjEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMTE+PJZ9awg\n"
                + "FhIKdmPkBtjBw3/L0CY45lpX5NmGq7SAmKkmpFyRlSacIaiSB/jbWXJWQAjQPWa4\n"
                + "oGGgTguUNKd8QmAfQ6NUZtOE2CqDNC8Hyrvzspq2OO81z1R87sOt1ykUXacWbhO/\n"
                + "OgqnHXe15zlC9vEAyR6NOP+dJ9BZYLYZAgMBAAGjUDBOMB0GA1UdDgQWBBSDSe00\n"
                + "oqoN/HaSSfyk5eZdlTI+bDAfBgNVHSMEGDAWgBSDSe00oqoN/HaSSfyk5eZdlTI+\n"
                + "bDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBALAc1iaduNaKef60h9Jv\n"
                + "9+JMqPCfezU2pfHk9LRbLdXGU0LUlDrx/nuTkKIlvkckhyNWBO4f8mJKIPdBz1Fe\n"
                + "9SYWRknWS5pukCfUjL0q1pL0B9AmcRCZp5jB6IiIbSTjaY+lU/ShIi1kwONGQwxY\n" + "WVPeQpg/5qNdlILbbvZ5ish1\n"
                + "-----END CERTIFICATE-----";

        String key = "-----BEGIN PRIVATE KEY-----\n"
                + "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMTE+PJZ9awgFhIK\n"
                + "dmPkBtjBw3/L0CY45lpX5NmGq7SAmKkmpFyRlSacIaiSB/jbWXJWQAjQPWa4oGGg\n"
                + "TguUNKd8QmAfQ6NUZtOE2CqDNC8Hyrvzspq2OO81z1R87sOt1ykUXacWbhO/Ogqn\n"
                + "HXe15zlC9vEAyR6NOP+dJ9BZYLYZAgMBAAECgYAUhkdBYEjT73Td5OF8geiE65Es\n"
                + "32GS2xSMD+b7GaUHavKBklpKnZTlNhv8rV7PgnHOD1kWkkIVWOTByirZ4lergeFR\n"
                + "gwU+dAgtt80aBd+4S4rSRTE8KTiJjNUbBHYbOPOLjnpQAiHYt2lS2DV84DDoQZIm\n"
                + "GLDU/t2NLVcIzQKUAQJBAOVd+vYbu3CdktfZajUBlp7ZEujMH9Sya0rSfhzja5of\n"
                + "XHSYAsTUoEQu7ndvJD3LgzDsbb5yDOTJa11JETdWdTkCQQDbngOho0gpCvJ7wbdb\n"
                + "KiAm6toGbMutq4+M93NNRx/KEJvdauw0K4tmmEhRhbDg5esBUuBTTp4HAtOBLEKm\n"
                + "yCfhAkBf8oNj5k/vmQrvXlSOXd67DkVZuuHp4MT/JLR6syu06j+LyncGDYgJXbSF\n"
                + "o6l+bB6yHYT+8MiyAAv4lvMrufAJAkAmHWBn9xyY8utuiwo1ajQ2TOAV6V/X/kRl\n"
                + "pLSAHu3ndcZ3QQ1JaJ1C6v7yFw/BmGWWzzlbe/N1KAppCrNumqJBAkEAsaG/a5bw\n"
                + "rijOTeOSaISSot3StqLnyUTWLgjvvtdPXgZnGrnfp4he2nVIpgUECJsm8+jctG1E\n" + "R6PvwhiDl4/yEA==\n"
                + "-----END PRIVATE KEY-----";

        String clientRandom = "F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2F2";
        String serverRandom = "2323232323232323232323232323232323232323232323232323232323232323";

        KeyStore ks = null;
        try {
            ks = keyStoreFromRsaPem(cert.getBytes(), key.getBytes());
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | CertificateException
                | KeyStoreException ex) {
            throw new IOException("Could not load key store from certificate data.", ex);
        }
        KeyPair kp = null;
        try {
            kp = keyPairFromStore(ks);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            throw new IOException("Could not load key pair from certificate data.", ex);
        }

        config.setPrivateKey(kp.getPrivate());
        ctx.setServerPublicKey(kp.getPublic());
        config.setOurCertificate(loadTLSCertificate(ks, TestCertificates.keyStoreAlias));

        ctx.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        ctx.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        ctx.setClientRandom(ArrayConverter.hexStringToByteArray(clientRandom));
        ctx.setServerRandom(ArrayConverter.hexStringToByteArray(serverRandom));

        List<NamedCurve> clientCurves = new ArrayList<>();
        clientCurves.add(NamedCurve.SECP384R1);
        List<NamedCurve> serverCurves = new ArrayList<>();
        serverCurves.add(NamedCurve.BRAINPOOLP256R1);
        serverCurves.add(NamedCurve.SECP384R1);
        serverCurves.add(NamedCurve.SECP256R1);
        ctx.setClientNamedCurvesList(clientCurves);
        config.setNamedCurves(serverCurves);

        List<ECPointFormat> clientFormats = new ArrayList<>();
        clientFormats.add(ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        clientFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        clientFormats.add(ECPointFormat.UNCOMPRESSED);
        List<ECPointFormat> serverFormats = new ArrayList<>();
        serverFormats.add(ECPointFormat.UNCOMPRESSED);
        ctx.setClientPointFormatsList(clientFormats);
        config.setPointFormats(serverFormats);

        List<SignatureAndHashAlgorithm> SigAndHashList = new LinkedList<>();
        SigAndHashList.add(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA512));
        config.setSupportedSignatureAndHashAlgorithms(SigAndHashList);

    }
}
