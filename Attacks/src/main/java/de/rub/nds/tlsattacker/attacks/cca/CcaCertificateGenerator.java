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
import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.translator.ParseNativeTypesContext;
import de.rub.nds.asn1tool.filesystem.TextFileReader;
import de.rub.nds.asn1tool.xmlparser.Asn1XmlContent;
import de.rub.nds.asn1tool.xmlparser.XmlParser;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDHPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDSAPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRSAPrivateKey;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.linker.Linker;
import de.rub.nds.x509attacker.xmlsignatureengine.XmlSignatureEngine;
import org.bouncycastle.crypto.tls.Certificate;
import sun.security.rsa.RSAPrivateCrtKeyImpl;

import javax.crypto.interfaces.DHPrivateKey;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static de.rub.nds.tlsattacker.core.certificate.PemUtil.readPrivateKey;
import static de.rub.nds.x509attacker.X509Attacker.*;

public class CcaCertificateGenerator {

    /**
     *
     * @param ccaDelegate
     * @param type
     * @return
     */
    public static CertificateMessage generateCertificate(CcaDelegate ccaDelegate, CcaCertificateType type)
            throws Exception {
        CertificateMessage certificateMessage = new CertificateMessage();
        if (type != null) {
            switch (type) {
                case CLIENT_INPUT:
                    List<CertificatePair> certificatePairsList = new LinkedList<>();
                    CertificatePair certificatePair = new CertificatePair(ccaDelegate.getClientCertificate());
                    certificatePairsList.add(certificatePair);
                    certificateMessage.setCertificatesList(certificatePairsList);
                    break;
                case EMPTY:
                    certificateMessage.setCertificatesListBytes(Modifiable.explicit(new byte[0]));
                    break;
                case ROOTv3_CAv3_LEAF_RSAv3:
                    certificateMessage = generateCertificateMessageFromXML("root-v3.pem", "ROOTv3_CAv3_LEAF_RSAv3.xml",
                            ccaDelegate.getKeyDirectory(), ccaDelegate.getXmlDirectory(),
                            ccaDelegate.getCertificateInputDirectory(), ccaDelegate.getCertificateOutputDirectory());
                    break;
                case ROOTv3_CAv3_LEAFv1_nLEAF_RSAv3:
                    certificateMessage = generateCertificateMessageFromXML("root-v3.pem",
                            "ROOTv3_CAv3_LEAFv1_nLEAF_RSAv3.xml", ccaDelegate.getKeyDirectory(),
                            ccaDelegate.getXmlDirectory(), ccaDelegate.getCertificateInputDirectory(),
                            ccaDelegate.getCertificateOutputDirectory());
                    break;
                case ROOTv1_CAv3_LEAFv1_nLEAF_RSAv3:
                    certificateMessage = generateCertificateMessageFromXML("root-v1.pem",
                            "ROOTv1_CAv3_LEAFv1_nLEAF_RSAv3.xml", ccaDelegate.getKeyDirectory(),
                            ccaDelegate.getXmlDirectory(), ccaDelegate.getCertificateInputDirectory(),
                            ccaDelegate.getCertificateOutputDirectory());
                    break;
                case debug:
                    certificateMessage = generateCertificateMessageFromXML("root-v1.pem",
                            "debug.xml", ccaDelegate.getKeyDirectory(),
                            ccaDelegate.getXmlDirectory(), ccaDelegate.getCertificateInputDirectory(),
                            ccaDelegate.getCertificateOutputDirectory());
                    break;
                default:
                    break;
            }
        }
        return certificateMessage;
    }

    /**
     * This function assumes that all paths and the corresponding files exist.
     * It will be the task of the Probe to ensure that those paths are at least
     * set. Exceptions should be handled by the Probe
     *
     * This function establishes a few conventions. 1.) First, for every
     * rootCertificate specifies there has to be a file with the same name in
     * the keyDirectory which is the corresponding PRIVATE key to the
     * certificate. 2.) Additionally several keys need to be present in the
     * keyDirectory. 3.) Furthermore, certificateChains are XML files that can
     * be processed by X509Attacker with the sole exception of two placeholders
     * which will be replaced. Those placeholders are '<asn1Sequence
     * identifier="issuer" type="Name" placeholder="replace_me"/>' and
     * 'replace_me_im_a_dummy_key'. The former is replaced with the subject of
     * the root certificate used and the latter with the path to the key of the
     * root certificate. Note that not the attribute is the placeholder but the
     * whole string. 4.) the leaf certificates keyInfo needs the keyType
     * attribute which is used to specify which type of key is used (RSA, DH,
     * DHE, DSA). Corresponding to the key used a naming convention has to be
     * followed (the autogen script already follows the convention) 5.) Last but
     * not least certificates have to be created in a certain order in the XML
     * file because the code uses the key corresponding to the first certificate
     * for the connection, aka it's supposed to be the leaf certificate. All
     * following certificates should be should be in ascending order, ending at
     * the bottom with the highest level CA.
     *
     * TODO: ASN.1 Parsing bugs for inspiration
     *
     *
     * TODO: Currently I do not ensure that the Directory variables end with a
     * slash. Maybe I should just add one since it should be ignored.
     *
     * @param rootCertificate
     * @param certificateChain
     * @param keyDirectory
     * @param xmlDirectory
     * @param certificateInputDirectory
     * @param certificateOutputDirectory
     * @return
     * @throws CertificateException
     * @throws IOException
     * @throws ParserException
     */
    private static CertificateMessage generateCertificateMessageFromXML(String rootCertificate,
            String certificateChain, String keyDirectory, String xmlDirectory, String certificateInputDirectory,
            String certificateOutputDirectory) throws Exception {

        keyDirectory = keyDirectory + "/";
        xmlDirectory = xmlDirectory + "/";
        certificateInputDirectory = certificateInputDirectory + "/";
        certificateOutputDirectory = certificateOutputDirectory + "/";

        String xmlSubject = extractXMLCertificateSubject(certificateInputDirectory + rootCertificate);

        TextFileReader textFileReader = new TextFileReader(xmlDirectory + certificateChain);
        String xmlString = textFileReader.read();

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
        keyFileManager.init(keyDirectory);

        // Create signatures
        XmlSignatureEngine xmlSignatureEngine = new XmlSignatureEngine(linker, identifierMap);
        xmlSignatureEngine.computeSignatures();

        // Declare variables for later use
        String keyName = "Default non existent key";
        String keyType = "";
        Boolean readKey = false;
        CertificateMessage certificateMessage = new CertificateMessage();
        List<CertificatePair> certificatePairList = new LinkedList<>();
        CertificatePair certificatePair;
        byte[] encodedLeafCertificate = {};
        CertificateKeyPair certificateKeyPair;
        byte[] keyBytes;
        PrivateKey privateKey;

        // Encode XML for certificate
        List<Asn1Encodable> certificates = asn1XmlContent.getAsn1Encodables();
        byte[][] encodedCertificates = new byte[certificates.size()][];
        for (int i = 0; i < certificates.size(); i++) {
            Asn1Encodable certificate = certificates.get(i);
            encodedCertificates[i] = Asn1EncoderForX509.encodeForCertificate(linker, certificate);
            if (certificate instanceof Asn1Sequence && readKey == false) {
                keyName = ((KeyInfo) ((Asn1Sequence) certificate).getChildren().get(0)).getKeyFile();
                keyType = ((Asn1Sequence) certificate).getChildren().get(0).getAttribute("keyType");
                encodedLeafCertificate = encodedCertificates[i];
                readKey = true;
            }
        }

        // Add certificates to pair list
        for (byte[] certificate : encodedCertificates) {
            if (certificate.length > 0) {
                certificatePair = new CertificatePair(certificate);
                certificatePairList.add(certificatePair);
            }
        }
        certificateMessage.setCertificatesList(certificatePairList);

        // Parse leaf certificate for CertificateKeyPair
        // Leads to the problem that unparsable certificates lead to an NPE
        // exception later (e.g. version 5) since
        // the Certificate couldn't be parsed.
        // TODO: see if there is a different way to convert this into a
        // certiicate object which is needed by TLS-Attacker/Scanner
        Certificate certificate = parseCertificate(encodedLeafCertificate.length, encodedLeafCertificate);

        // Parse private key and instantiate correct CertificateKeyPair

        switch (keyType) {
            /**
             *
             * TODO: replace types with enum
             */
            case "RSA":
                keyBytes = keyFileManager.getKeyFileContent(keyName);
                privateKey = readPrivateKey(new ByteArrayInputStream(keyBytes));
                BigInteger modulus = ((RSAPrivateCrtKeyImpl) privateKey).getModulus();
                BigInteger d = ((RSAPrivateCrtKeyImpl) privateKey).getPrivateExponent();
                certificateKeyPair = new CertificateKeyPair(certificate, new CustomRSAPrivateKey(modulus, d));
                break;
            case "DH":
                keyBytes = keyFileManager.getKeyFileContent(keyName.replace("pub", ""));
                privateKey = readPrivateKey(new ByteArrayInputStream(keyBytes));

                BigInteger x = ((DHPrivateKey) privateKey).getX();
                BigInteger p = ((DHPrivateKey) privateKey).getParams().getP();
                BigInteger g = ((DHPrivateKey) privateKey).getParams().getG();
                certificateKeyPair = new CertificateKeyPair(certificate, new CustomDHPrivateKey(x, p, g));
                break;
            case "DSA":
                keyBytes = keyFileManager.getKeyFileContent(keyName);
                privateKey = readPrivateKey(new ByteArrayInputStream(keyBytes));

                BigInteger x2 = ((DSAPrivateKey) privateKey).getX();
                BigInteger primeP = ((DSAPrivateKey) privateKey).getParams().getP();
                BigInteger primeQ = ((DSAPrivateKey) privateKey).getParams().getQ();
                BigInteger generator = ((DSAPrivateKey) privateKey).getParams().getG();
                certificateKeyPair = new CertificateKeyPair(certificate, new CustomDSAPrivateKey(x2, primeP, primeQ,
                        generator));
                break;
            case "ECDH":
            case "ECDSA":
            case "KEA":
            default:
                throw new Exception("Unknown or unsupported value for keyType attribute of keyInfo in XMLCertificate.");
        }

        certificateMessage.setCertificateKeyPair(certificateKeyPair);

        // Write certificate files such that test cases can be reproduced
        // without TLS-Scanner with exactly the same certificates
        writeCertificates(certificateOutputDirectory, certificates, encodedCertificates);

        return certificateMessage;
    }

    private static String extractXMLCertificateSubject(String rootCertificate) throws CertificateException,
            IOException, ParserException {
        // Register XmlClasses, Types, Contexts and Unpackers
        registerXmlClasses();
        registerTypes();
        registerContexts();
        registerContentUnpackers();

        // Load X.509 root certificate and get Subject principal
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream(rootCertificate);
        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        X500Principal x500PrincipalSubject = x509Certificate.getSubjectX500Principal();

        byte[] encodedSubject = x500PrincipalSubject.getEncoded();
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : encodedSubject) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    private static Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                    ArrayConverter.intToBytes(lengthBytes + 3, 3), ArrayConverter.intToBytes(lengthBytes, 3),
                    bytesToParse));
            return Certificate.parse(stream);
        } catch (Exception E) {
            return null;
        }
    }

}
