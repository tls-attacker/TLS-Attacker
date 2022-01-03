/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.certificate.PemUtil;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import java.io.*;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateException;

import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author
 */
public class EmptyClientKeyExchangePreparatorTest {
    /*
     * In case you need to re-create the certificates or PMS parameters, follow these instructions (execute them in the
     * OpenSSL ./demos/certs/ folder and execute `bash cert.sh` beforehand to generate the CA). 0) run `bash cert.sh` to
     * create the DH keys and cert along with the CA 1) create EC key params: openssl genpkey -genparam -algorithm EC
     * -pkeyopt ec_paramgen_curve:P-256 -out ecp.pem 2) create and extract EC client keys: openssl genpkey -paramfile
     * ecp.pem -out ec_client_keys.pem openssl pkey -in ec_client_keys.pem -out ec_client_privkey.pem openssl pkey -in
     * ec_client_keys.pem -pubout -out ec_client_pubkey.pem 3) create and sign client cert: CN="Test Client DH Cert"
     * openssl req -config ca.cnf -new -key ec_client_keys.pem -out ec_client_req.pem openssl x509 -req -in
     * ec_client_req.pem -CA root.pem -days 3600 -force_pubkey ec_client_pubkey.pem -extfile ca.cnf -extensions dh_cert
     * -CAcreateserial -out ec_client.crt 4) create and extract EC server keys: openssl genpkey -paramfile ecp.pem -out
     * ec_server_keys.pem openssl pkey -in ec_server_keys.pem -out ec_server_privkey.pem openssl pkey -in
     * ec_server_keys.pem -pubout -out ec_server_pubkey.pem 5) derive the EC shared secret: openssl pkeyutl -derive
     * -inkey ec_client_privkey.pem -peerkey ec_server_pubkey.pem -hexdump To get the actual key values that are needed
     * here, you can use this OpenSSL command: openssl pkey -in <file> -noout -text
     */

    private static final Logger LOGGER = LogManager.getLogger();

    private final String RANDOM = "AABBCCDDEEFF";

    private final String DH_CLIENT_CERT =
        "-----BEGIN CERTIFICATE-----\n" + "MIIDazCCAlOgAwIBAgIUJgpWox2D+qdKWJR8bcl4tmz2CUQwDQYJKoZIhvcNAQEL\n"
            + "BQAwPDELMAkGA1UEBhMCVUsxFjAUBgNVBAoMDU9wZW5TU0wgR3JvdXAxFTATBgNV\n"
            + "BAMMDFRlc3QgUm9vdCBDQTAeFw0yMDEwMDIxNjM5MDdaFw0zMDA4MTExNjM5MDda\n"
            + "MEMxCzAJBgNVBAYTAlVLMRYwFAYDVQQKDA1PcGVuU1NMIEdyb3VwMRwwGgYDVQQD\n"
            + "DBNUZXN0IENsaWVudCBESCBDZXJ0MIIBIDCBlQYJKoZIhvcNAQMBMIGHAoGBAMbf\n"
            + "7WJaA+gIWqfYKNTqnK36ugZm/gBMI121tVusfT0fgDVO7G1pEd9ClCAoh2ahviUM\n"
            + "kgKLX13lOw5/rSUXexg9biURJKx4hoscxKra9WAWh4PZwxbDkfQ6pz6a+UxARJwF\n"
            + "mWvWrEDuKbeq2KrG3M1HA4o7fzAAMjl6qzFce+vTAgECA4GFAAKBgQC+udq0WkMr\n"
            + "DQkbjNC7ZmUMCo4rEJO2UgAfHKN271bzmRIAFfHFKHIfTojg6WGhrWcaFIW6nqtA\n"
            + "N67WEaHacpweCpHtCvPxnnUjH1XbL0cwi3W24FDYtZRxvOPhjon2nSwPTVL+Uooi\n"
            + "X9HxCZIyCelJ8dTREBMyyxXskAD157Awf6NgMF4wDAYDVR0TAQH/BAIwADAOBgNV\n"
            + "HQ8BAf8EBAMCAwgwHQYDVR0OBBYEFKIgwjuuHrtoA7ju/BFRuAhBFF3XMB8GA1Ud\n"
            + "IwQYMBaAFDKEkFkqw5dU5CJeF6cLoEijG326MA0GCSqGSIb3DQEBCwUAA4IBAQCl\n"
            + "kzwIBKLlbNs62qOJa65+JmUSVcBnEGuMZqVg7Lbk8is/2LOkyTD1gMIfWbPCSKDx\n"
            + "TFOYn6XReVLLGzgz1+jDUD2fc8kQ/4iIk2UauTQ69UYqAVLfDyH5aNhgxN8kThiY\n"
            + "fIsth6Yp49kvN0dXch7etQxjKsNsDGD8hocyTdawk9BB+CWnIcXhi8dhHVMOfN4e\n"
            + "bbNRbeHFR45FbYJ4jscFkH4uVGgxsY08Q7XukHuavNl/U3mqlzs1dqEt8TZ8V/q/\n"
            + "zvqwTMlVYf2i0XSSARZcOoNzkJSUVZ06k6SvqtMn5TuPkZBcAO1NzJAVphadZnZn\n" + "cPmrAM5NZ93Yb1hvcDPP\n"
            + "-----END CERTIFICATE-----\n";
    private final BigInteger DH_CLIENT_PRIVATE_KEY = new BigInteger(
        "51779b5a2fdbf2a877ab7ff627b619bb3a01c83c69edc69a0b94ff2019a621063cd1033a14aef00d28617fab2b60a26a40c66702ccaf60d5ef3539c884fa341ccb03efa9d63566d4cd954f1455f2af5c185939192f2368141eecd08b93aa7ba614048b36dfdedd76a628e2414eaefaeacd3bb3df2b595dfed5b48f2ec3e11377",
        16);
    private final BigInteger DH_SERVER_PUBLIC_KEY = new BigInteger(
        "4bacb3c2b27d0abecd1928125d1f531170b4606ebf79e85326e26e0aed2c620e1d5ad26a12bb3b172de9fbd761f83b7d34f51e1830dae9cf54b8b3938441b8e4a6a080ed76f90be5e95e082fc4f8cd51f1205c73799c02e26c5c019ad1e4efda7b12c96dbdae7a07492cb326063e95c9fc03b572482b6aa046da81daf235ddb0",
        16);
    private final byte[] DH_PREMASTER = ArrayConverter.hexStringToByteArray(
        "94d76287236c384db4a712b1ae996da7e8cc19c8a38cac6e8245404106f1c7094a0806470abafe884bab0073821f2d04ebf989f33f688280146bf97267b0e08c93a34dbfb3a59747b0dc97670bfc7ecb9332312cf2599d67944dad9576dfd29ca334a006c2abfb883d8645e54ad8f4fd229ec231714a7c8bcf1392c244c14e90");

    private final String EC_CLIENT_CERT =
        "-----BEGIN CERTIFICATE-----\n" + "MIICojCCAYqgAwIBAgIUJgpWox2D+qdKWJR8bcl4tmz2CUUwDQYJKoZIhvcNAQEL\n"
            + "BQAwPDELMAkGA1UEBhMCVUsxFjAUBgNVBAoMDU9wZW5TU0wgR3JvdXAxFTATBgNV\n"
            + "BAMMDFRlc3QgUm9vdCBDQTAeFw0yMDEwMDcxNTI2MzFaFw0zMDA4MTYxNTI2MzFa\n"
            + "MEMxCzAJBgNVBAYTAlVLMRYwFAYDVQQKDA1PcGVuU1NMIEdyb3VwMRwwGgYDVQQD\n"
            + "DBNUZXN0IENsaWVudCBESCBDZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
            + "vwo9HN4FWaQxkUFReNaCl96RE+oWgzRcjF+Aek2/5n8U4cJid85NRY+gGIm+8lbT\n"
            + "anZyA5O4wLQiYJqBgLyDM6NgMF4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMC\n"
            + "AwgwHQYDVR0OBBYEFEOC/+UuMlN/2NrZxt/vZEWgjhFJMB8GA1UdIwQYMBaAFDKE\n"
            + "kFkqw5dU5CJeF6cLoEijG326MA0GCSqGSIb3DQEBCwUAA4IBAQCe/1VgAiRKYWCT\n"
            + "75ZBUYQP7Gjvns3vSGKOBqYqbyeR9ZUZyzT8X6MOmMmbXdrqkSFDpU6UYoDj4wQZ\n"
            + "TFwkUlpVq0sq+ZgNm5P20BMQUHEkL4wU+dlbMrwaUMRv5e8lqAcauKche+PgpRuP\n"
            + "/m1jl/akhHdNpcslSm/rKpyAnugx7bMO/txwb5bafKoV+033VDMQinamSghBPqBO\n"
            + "/wAvHK8xxM0eUAFubZcRrNoWrOhQl4y0oSVK51o6iI7dWsPBseQbkgNovPiTx8U/\n"
            + "XLryfayzwwQ6SGroiSVYoJ+/NCuvkWt3mshhJD2j+8ilKeBxG4GLiDRPzvCUAekD\n" + "cVSrB7DJ\n"
            + "-----END CERTIFICATE-----";
    private final BigInteger EC_CLIENT_PRIVATE_KEY =
        new BigInteger("ec20862b9bbfa1d27ac4654cbf4ed38858562827e8e75408366288d1e252ba6d", 16);
    private final byte[] EC_SERVER_PUBLIC_KEY_BYTES = ArrayConverter.hexStringToByteArray(
        "0459c8daa2f6828f780c9e83a112b3e9bff2bb859e9fc65be2243f03b81f33e6375fd77e401288b70ac4d5b3a4a81332078e1374287c7adf2e6b36dcf4cc6af234");
    private final byte[] EC_PREMASTER =
        ArrayConverter.hexStringToByteArray("26d7439f907fbd24408203579f7c712b04ee2aa55e62734adda2ecb904c6da0a");

    private TlsContext context;
    private EmptyClientKeyExchangePreparator preparator;
    private EmptyClientKeyExchangeMessage message;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());

        context = new TlsContext();
        context.setHighestClientProtocolVersion(ProtocolVersion.TLS12);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        context.setClientRandom(ArrayConverter.hexStringToByteArray(RANDOM));
        context.setServerRandom(ArrayConverter.hexStringToByteArray(RANDOM));

        message = new EmptyClientKeyExchangeMessage();
        preparator = new EmptyClientKeyExchangePreparator(context.getChooser(), message);
    }

    @Test
    public void testPrepareHandshakeMessageNoClientCertificate() {
        context.setClientCertificate(Certificate.EMPTY_CHAIN);

        preparator.prepareHandshakeMessageContents();

        // PMS SHOULD not be calculatable without client key information
        Assert.assertNull(message.getComputations().getPremasterSecret());

        // check client and server random are correctly set and concatenated
        Assert.assertArrayEquals(
            ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray(RANDOM),
                ArrayConverter.hexStringToByteArray(RANDOM)),
            message.getComputations().getClientServerRandom().getValue());
    }

    @Test
    public void testPrepareHandshakeMessageContentsDH() throws CertificateException, IOException {
        // prepare message params
        context.setSelectedCipherSuite(CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA);
        context.setServerDhPublicKey(DH_SERVER_PUBLIC_KEY);

        // parse and set client certificate
        Certificate clientCertificate = PemUtil.readCertificate(new ByteArrayInputStream(DH_CLIENT_CERT.getBytes()));
        context.setClientCertificate(clientCertificate);

        // create certificate pair and trigger extraction of parameters
        CertificateKeyPair pair = new CertificateKeyPair(clientCertificate);
        pair.adjustInContext(context, ConnectionEndType.CLIENT);

        // set DH private key
        context.setClientDhPrivateKey(DH_CLIENT_PRIVATE_KEY);

        // test
        preparator.prepareHandshakeMessageContents();

        // check client and server random are correctly set and concatenated
        Assert.assertArrayEquals(
            ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray(RANDOM),
                ArrayConverter.hexStringToByteArray(RANDOM)),
            message.getComputations().getClientServerRandom().getValue());

        // check PMS correctly calculated
        Assert.assertArrayEquals(DH_PREMASTER, message.getComputations().getPremasterSecret().getValue());
    }

    @Test
    public void testPrepareHandshakeMessageContentsECDSA() throws CertificateException, IOException {
        // prepare message params
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);

        // parse and set client certificate
        Point pubKey = PointFormatter.formatFromByteArray(context.getChooser().getSelectedNamedGroup(),
            EC_SERVER_PUBLIC_KEY_BYTES);
        context.setServerEcPublicKey(pubKey);

        // parse and set client certificate
        Certificate clientCertificate = PemUtil.readCertificate(new ByteArrayInputStream(EC_CLIENT_CERT.getBytes()));
        context.setClientCertificate(clientCertificate);

        // create certificate pair and trigger extraction of parameters
        CertificateKeyPair pair = new CertificateKeyPair(clientCertificate);
        pair.adjustInContext(context, ConnectionEndType.CLIENT);

        // set EC private key
        context.setClientEcPrivateKey(EC_CLIENT_PRIVATE_KEY);

        // test
        preparator.prepareHandshakeMessageContents();

        // check client and server random are correctly set and concatenated
        Assert.assertArrayEquals(
            ArrayConverter.concatenate(ArrayConverter.hexStringToByteArray(RANDOM),
                ArrayConverter.hexStringToByteArray(RANDOM)),
            message.getComputations().getClientServerRandom().getValue());

        // check PMS correctly calculated
        Assert.assertArrayEquals(EC_PREMASTER, message.getComputations().getPremasterSecret().getValue());
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
