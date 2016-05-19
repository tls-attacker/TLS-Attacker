/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <HandshakeMessage>
 */
public class CertificateHandler<HandshakeMessage extends CertificateMessage> extends
	HandshakeMessageHandler<HandshakeMessage> {

    public CertificateHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = CertificateMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
	try {
	    // todo try to find a better solution for converting sun -> bc
	    // certificates
	    String alias = tlsContext.getAlias();
	    java.security.cert.Certificate sunCert = tlsContext.getKeyStore().getCertificate(alias);
	    if (alias == null || sunCert == null) {
		throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
			+ "certificate alias and key? (Current alias: " + alias + ")");
	    }
	    byte[] certBytes = sunCert.getEncoded();

	    ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
	    org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);

	    org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[1];
	    certs[0] = cert;
	    Certificate tlsCerts = new Certificate(certs);

	    X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));
	    protocolMessage.setX509CertificateObject(x509CertObject);

	    if (protocolMessage.getMessageIssuer() == ConnectionEnd.SERVER) {
		tlsContext.setServerCertificate(tlsCerts.getCertificateAt(0));
		tlsContext.setX509ServerCertificateObject(x509CertObject);
	    } else {
		tlsContext.setClientCertificate(tlsCerts.getCertificateAt(0));
		tlsContext.setX509ClientCertificateObject(x509CertObject);
	    }

	    ByteArrayOutputStream tlsCertBos = new ByteArrayOutputStream();
	    tlsCerts.encode(tlsCertBos);
	    protocolMessage.setX509CertificateBytes(tlsCertBos.toByteArray());

	    // byte[] x509CertBytes = x509CertObject.getEncoded();
	    protocolMessage.setCertificatesLength(protocolMessage.getX509CertificateBytes().getValue().length
		    - HandshakeByteLength.CERTIFICATES_LENGTH);
	    // protocolMessage.setLength(protocolMessage.getCertificatesLength().getValue()
	    // + HandshakeByteLength.CERTIFICATES_LENGTH);
	    // BC implicitly includes the certificates length of all the
	    // certificates, so we only need to set the protocol message length

	    protocolMessage.setLength(protocolMessage.getX509CertificateBytes().getValue().length);
	    byte[] result = protocolMessage.getX509CertificateBytes().getValue();

	    long header = (protocolMessage.getHandshakeMessageType().getValue() << 24)
		    + protocolMessage.getLength().getValue();
	    protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
		    ArrayConverter.longToUint32Bytes(header), result));

	    return protocolMessage.getCompleteResultingMessage().getValue();

	} catch (KeyStoreException | CertificateEncodingException | IOException | CertificateParsingException ex) {
	    throw new ConfigurationException("Certificate with the selected alias could not be found", ex);
	}
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	if (message[pointer] != HandshakeMessageType.CERTIFICATE.getValue()) {
	    throw new InvalidMessageTypeException("This is not a certificate message");
	}
	protocolMessage.setType(message[pointer]);

	int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
	int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
	int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setLength(length);

	currentPointer = nextPointer;
	nextPointer = currentPointer + HandshakeByteLength.CERTIFICATES_LENGTH;
	int certificatesLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
	protocolMessage.setCertificatesLength(certificatesLength);

	try {
	    Certificate tlsCerts = Certificate.parse(new ByteArrayInputStream(message, currentPointer, protocolMessage
		    .getCertificatesLength().getValue() + HandshakeByteLength.CERTIFICATES_LENGTH));
	    X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));
	    protocolMessage.setX509CertificateObject(x509CertObject);
	    if (protocolMessage.getMessageIssuer() == ConnectionEnd.SERVER) {
		tlsContext.setServerCertificate(tlsCerts.getCertificateAt(0));
		tlsContext.setX509ServerCertificateObject(x509CertObject);
	    } else {
		tlsContext.setClientCertificate(tlsCerts.getCertificateAt(0));
		tlsContext.setX509ClientCertificateObject(x509CertObject);
	    }
	} catch (IOException | CertificateParsingException ex) {
	    throw new WorkflowExecutionException(ex.getLocalizedMessage(), ex);
	}
	nextPointer = nextPointer + protocolMessage.getCertificatesLength().getValue();

	protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

	return nextPointer;
    }
}
