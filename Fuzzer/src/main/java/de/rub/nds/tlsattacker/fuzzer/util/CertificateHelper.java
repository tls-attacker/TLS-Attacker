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
package de.rub.nds.tlsattacker.fuzzer.util;

import de.rub.nds.tlsattacker.fuzzer.config.SimpleFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.impl.SimpleFuzzer;
import de.rub.nds.tlsattacker.tls.config.ClientConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CertificateParsingException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class CertificateHelper {

    private static final Logger LOGGER = LogManager.getLogger(CertificateHelper.class);

    private CertificateHelper() {

    }

    /**
     * Fetches the server certificate
     * 
     * @param config
     * @return server certificate if possible. If no server certificate message
     *         was received, throws a configuration exception.
     */
    public static Certificate fetchCertificate(SimpleFuzzerConfig config) {
	ConfigHandler configHandler = new ClientConfigHandler();
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	try {
	    workflowExecutor.executeWorkflow();
	    return tlsContext.getServerCertificate();
	} catch (Exception e) {
	    SimpleFuzzer.LOGGER.debug(e);
	    transportHandler.closeConnection();
	    throw new ConfigurationException(
		    "No server certificate was fetched. Was the handshake executed correctly? Execute the program again.",
		    e);
	}
    }

    /**
     * 
     * @param context
     * @return
     */
    public static boolean containsModifiedCertificate(TlsContext context) {
	WorkflowTrace trace = context.getWorkflowTrace();
	List<Integer> certificatePositions = trace.getHandshakeMessagePositions(HandshakeMessageType.CERTIFICATE);
	for (Integer i : certificatePositions) {
	    CertificateMessage certMessage = (CertificateMessage) trace.getProtocolMessages().get(i);
	    if (certMessage.getX509CertificateBytes() != null
		    && certMessage.getX509CertificateBytes().isOriginalValueModified()) {
		return true;
	    }
	}
	return false;
    }

    /**
     * Writes modification information into the file
     * 
     * @param context
     * @param fileName
     */
    public static void writeModifiedCertInfoToFile(TlsContext context, String fileName) {
	WorkflowTrace trace = context.getWorkflowTrace();
	List<Integer> certificatePositions = trace.getHandshakeMessagePositions(HandshakeMessageType.CERTIFICATE);
	for (Integer i : certificatePositions) {
	    CertificateMessage certMessage = (CertificateMessage) trace.getProtocolMessages().get(i);
	    if (certMessage.getX509CertificateBytes() != null
		    && certMessage.getX509CertificateBytes().isOriginalValueModified()) {
		try {
		    FileWriter fw = new FileWriter(fileName);
		    try {
			ASN1Primitive asn1Cert = TlsUtils.readDERObject(certMessage.getX509CertificateBytes()
				.getValue());
			org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
				.getInstance(asn1Cert);

			org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[1];
			certs[0] = cert;
			org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(
				certs);

			X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));

			fw.append(x509CertObject.toString());
		    } catch (CertificateParsingException | IOException ex) {
			ex.printStackTrace(new PrintWriter(fw));
		    } finally {
			fw.close();
		    }
		} catch (IOException e) {
		    LOGGER.warn(e);
		}
	    }
	}
    }

}
