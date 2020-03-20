/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.KeyInfo;
import de.rub.nds.asn1tool.xmlparser.Asn1XmlContent;
import de.rub.nds.asn1tool.xmlparser.XmlParser;
import de.rub.nds.tlsattacker.core.certificate.PemUtil;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.keys.*;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.linker.Linker;
import de.rub.nds.x509attacker.xmlsignatureengine.XmlSignatureEngine;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.AbstractMap.SimpleEntry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static de.rub.nds.tlsattacker.core.certificate.PemUtil.readPrivateKey;
import static de.rub.nds.tlsattacker.core.certificate.PemUtil.readPublicKey;
import static de.rub.nds.x509attacker.X509Attacker.*;

public class CcaCertificateManager {

    private static Logger LOGGER = LogManager.getLogger();

    private static CcaCertificateManager reference = null;
    private final Map<CcaCertificateType, Entry<byte[][], Entry<CustomPrivateKey, CustomPublicKey>>> certificateKeyMap = new HashMap<>();
    private CcaDelegate ccaDelegate = null;

    private CcaCertificateManager(CcaDelegate ccaDelegate) {
        this.init(ccaDelegate);
    }

    public static CcaCertificateManager getReference(CcaDelegate ccaDelegate) {
        if (reference == null) {
            synchronized (CcaCertificateManager.class) {
                if (reference == null) {
                    reference = new CcaCertificateManager(ccaDelegate);
                }
            }
        }
        // }
        // return reference;
        // if (reference == null) {
        // reference = new CcaCertificateManager();
        // }
        return reference;
    }

    private static String extractXMLCertificateSubject(String certificateInputDirectory, String rootCertificate) {
        // Register XmlClasses and Types
        registerXmlClasses();
        registerTypes();

        Logger LOGGER = LogManager.getLogger();
        CcaFileManager ccaFileManager = CcaFileManager.getReference(certificateInputDirectory);

        // Load X.509 root certificate and get Subject principal
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
                    ccaFileManager.getFileContent(rootCertificate));
            X509Certificate x509Certificate = (X509Certificate) certificateFactory
                    .generateCertificate(byteArrayInputStream);
            X500Principal x500PrincipalSubject = x509Certificate.getSubjectX500Principal();
            byte[] encodedSubject = x500PrincipalSubject.getEncoded();
            StringBuilder stringBuilder = new StringBuilder();
            for (byte b : encodedSubject) {
                stringBuilder.append(String.format("%02x", b));
            }
            return stringBuilder.toString();

        } catch (CertificateException ce) {
            LOGGER.error("Error while either instantiating X.509 CertificateFactory or generating certificate from "
                    + "fileInputStream. " + ce);
            return null;
        }
    }

    public void init(CcaDelegate ccaDelegate) {
        this.ccaDelegate = ccaDelegate;
        for (CcaCertificateType ccaCertificateType : CcaCertificateType.values()) {
            if (ccaCertificateType.getRequiresCaCertAndKeys()) {
                this.certificateKeyMap.put(ccaCertificateType, generateCertificateListFromXML(ccaCertificateType));
            } else if (ccaCertificateType.getRequiresCertificate()) {
                this.certificateKeyMap.put(
                        ccaCertificateType,
                        new SimpleEntry<byte[][], Entry<CustomPrivateKey, CustomPublicKey>>(new byte[][] { ccaDelegate
                                .getClientCertificate() }, null));
            } else {
                this.certificateKeyMap.put(ccaCertificateType,
                        new SimpleEntry<byte[][], Entry<CustomPrivateKey, CustomPublicKey>>(
                                new byte[][] { new byte[0] }, null));
            }
        }
    }

    public Entry<byte[][], Entry<CustomPrivateKey, CustomPublicKey>> getCertificateList(
            CcaCertificateType ccaCertificateType) {
        if (this.certificateKeyMap.containsKey(ccaCertificateType)) {
            return this.certificateKeyMap.get(ccaCertificateType);
        } else {
            LOGGER.error("Entry for " + ccaCertificateType + " is not available in CcaCertificateManager!");
        }
        return null;
    }

    private Entry<byte[][], Entry<CustomPrivateKey, CustomPublicKey>> generateCertificateListFromXML(
            CcaCertificateType ccaCertificateType) {

        // Logger for errors
        Logger LOGGER = LogManager.getLogger();

        // Declare variables for later use
        String keyName = "Default non existent key";
        String pubKeyName = "Default non existent key";
        String keyType = "";
        Boolean readKey = false;
        CertificateMessage certificateMessage = new CertificateMessage();
        String rootCertificate = ccaCertificateType.toString().split("_")[0].toLowerCase() + ".pem";
//        String rootCertificate = ccaCertificateType.toString().substring(0, 6).toLowerCase() + ".pem";
        CustomPrivateKey customPrivateKey;
        CustomPublicKey customPublicKey;
        byte[] keyBytes;
        byte[] pubKeyBytes;
        PrivateKey privateKey;

        // Input/Output directories
        String keyDirectory = ccaDelegate.getKeyDirectory() + "/";
        String xmlDirectory = ccaDelegate.getXmlDirectory() + "/";
        String certificateInputDirectory = ccaDelegate.getCertificateInputDirectory() + "/";
        String certificateOutputDirectory = ccaDelegate.getCertificateOutputDirectory() + "/";

        // Get the corresponding CcaFileManager
        CcaFileManager ccaFileManager = CcaFileManager.getReference(xmlDirectory);

        // Get the Subject of the root certificate as an XML string
        String xmlSubject = extractXMLCertificateSubject(certificateInputDirectory, rootCertificate);

        String xmlString = new String(ccaFileManager.getFileContent(ccaCertificateType.toString() + ".xml"));

        if (xmlString == null) {
            LOGGER.error("Failed to get content of XML file.");
            return null;
        }

        String needle = "<asn1RawBytes identifier=\"issuer\" type=\"RawBytes\" placeholder=\"replace_me\"><value>";
        String replacement = "<asn1RawBytes identifier=\"issuer\" type=\"RawBytes\"><value>";
        xmlString = xmlString.replace(needle, replacement + xmlSubject);
        // Please note that rootCertificate always has to be a filename only. No
        // path
        xmlString = xmlString.replace("replace_me_im_a_dummy_key", rootCertificate);

        // Parse XML
        XmlParser xmlParser = new XmlParser(xmlString);
        Asn1XmlContent asn1XmlContent = xmlParser.getAsn1XmlContent();
        Map<String, Asn1Encodable> identifierMap = xmlParser.getIdentifierMap();

        // Create links
        Linker linker = new Linker(identifierMap);

        // Load key files
        KeyFileManager keyFileManager = KeyFileManager.getReference();
        try {
            keyFileManager.init(keyDirectory);
        } catch (KeyFileManagerException kfme) {
            LOGGER.error("Failed to initialize KeyFileManager. " + kfme);
        }

        // Create signatures
        XmlSignatureEngine xmlSignatureEngine = new XmlSignatureEngine(linker, identifierMap);
        xmlSignatureEngine.computeSignatures();

        // Encode XML for certificate
        List<Asn1Encodable> certificates = asn1XmlContent.getAsn1Encodables();
        byte[][] encodedCertificates = new byte[certificates.size()][];
        for (int i = 0; i < certificates.size(); i++) {
            Asn1Encodable certificate = certificates.get(i);
            encodedCertificates[i] = Asn1EncoderForX509.encodeForCertificate(linker, certificate);
            if (certificate instanceof Asn1Sequence && readKey == false) {
                keyName = ((KeyInfo) ((Asn1Sequence) certificate).getChildren().get(0)).getKeyFile();
                pubKeyName = ((KeyInfo) ((Asn1Sequence) certificate).getChildren().get(0)).getPubKeyFile();
                keyType = ((Asn1Sequence) certificate).getChildren().get(0).getAttribute("keyType");
                readKey = true;
            }
        }

        // Parse private key and instantiate correct CustomPrivateKey
        CcaCertificateKeyType ccaCertificateKeyType = CcaCertificateKeyType.fromJavaName(keyType.toLowerCase());
        try {
            switch (ccaCertificateKeyType) {
                case RSA:
                    keyBytes = keyFileManager.getKeyFileContent(keyName);

                    privateKey = readPrivateKey(new ByteArrayInputStream(keyBytes));
                    BigInteger modulus = ((RSAPrivateCrtKeyImpl) privateKey).getModulus();
                    BigInteger d = ((RSAPrivateCrtKeyImpl) privateKey).getPrivateExponent();
                    customPrivateKey = new CustomRSAPrivateKey(modulus, d);

                    pubKeyBytes = keyFileManager.getKeyFileContent(pubKeyName);

                    PublicKey publicKey = PemUtil.readPublicKey(new ByteArrayInputStream(pubKeyBytes));
                    customPublicKey = new CustomRsaPublicKey(((RSAPublicKeyImpl) publicKey).getPublicExponent(),
                            modulus);
                    break;
                case DH:
                    keyBytes = keyFileManager.getKeyFileContent(keyName);
                    privateKey = readPrivateKey(new ByteArrayInputStream(keyBytes));

                    pubKeyBytes = keyFileManager.getKeyFileContent(pubKeyName);
                    publicKey = readPublicKey(new ByteArrayInputStream(pubKeyBytes));

                    BigInteger y = ((DHPublicKey) publicKey).getY();
                    BigInteger x = ((DHPrivateKey) privateKey).getX();
                    BigInteger p = ((DHPrivateKey) privateKey).getParams().getP();
                    BigInteger g = ((DHPrivateKey) privateKey).getParams().getG();
                    customPrivateKey = new CustomDHPrivateKey(x, p, g);
                    customPublicKey = new CustomDhPublicKey(p, g, y);
                    break;
                case DSA:
                    keyBytes = keyFileManager.getKeyFileContent(keyName);
                    privateKey = readPrivateKey(new ByteArrayInputStream(keyBytes));
                    publicKey = readPublicKey(new ByteArrayInputStream(keyBytes));

                    BigInteger y2 = ((DSAPublicKey) publicKey).getY();
                    BigInteger x2 = ((DSAPrivateKey) privateKey).getX();
                    BigInteger primeP = ((DSAPrivateKey) privateKey).getParams().getP();
                    BigInteger primeQ = ((DSAPrivateKey) privateKey).getParams().getQ();
                    BigInteger generator = ((DSAPrivateKey) privateKey).getParams().getG();
                    customPrivateKey = new CustomDSAPrivateKey(x2, primeP, primeQ, generator);
                    customPublicKey = new CustomDsaPublicKey(primeP, primeQ, generator, y2);
                    break;
                case ECDH:
                case ECDSA:
                    keyBytes = keyFileManager.getKeyFileContent(keyName);
                    privateKey = readPrivateKey(new ByteArrayInputStream(keyBytes));
                    pubKeyBytes = keyFileManager.getKeyFileContent(pubKeyName);
                    publicKey = readPublicKey(new ByteArrayInputStream(pubKeyBytes));

                    ECPoint x3 = ((ECPublicKey) publicKey).getW();
                    BigInteger pKey = ((ECPrivateKey) privateKey).getS();
                    NamedGroup nGroup = NamedGroup.getNamedGroup((ECPrivateKey) privateKey);
                    customPrivateKey = new CustomECPrivateKey(pKey, nGroup);
                    customPublicKey = new CustomEcPublicKey(x3.getAffineX(), x3.getAffineY(), nGroup);
                    break;
                case KEA:
                default:
                    LOGGER.error("Unknown or unsupported value for keyType attribute of keyInfo in XMLCertificate.");
                    return null;
            }
        } catch (IOException ioe) {
            LOGGER.error("IOException occurred while preparing PrivateKey. " + ioe);
            return null;
        } catch (KeyFileManagerException kfme) {
            LOGGER.error("Couldn't read key from KeyFileManager. " + kfme);
            return null;
        }

        // Write certificates to the output directory
        try {
            writeCertificates(certificateOutputDirectory, certificates, encodedCertificates);
        } catch (IOException ioe) {
            LOGGER.error("Couldn't write certificates to output directory. " + ioe);
            return null;
        }
        return new SimpleEntry<>(encodedCertificates, (Entry<CustomPrivateKey, CustomPublicKey>) (new SimpleEntry<>(
                customPrivateKey, customPublicKey)));
    }
}
