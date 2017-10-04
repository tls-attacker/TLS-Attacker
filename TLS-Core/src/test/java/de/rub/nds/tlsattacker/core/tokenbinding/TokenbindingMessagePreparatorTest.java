/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Security;
import java.util.Base64;
import java.util.Random;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TokenbindingMessagePreparatorTest {

    private TlsContext context;

    private Config config;

    private Chooser chooser;

    private TokenBindingMessage message;

    private TokenbindingMessagePreparator preparator;

    @Before
    public void setUp() {
        config = Config.createConfig();
        context = new TlsContext(config);
        chooser = context.getChooser();
        message = new TokenBindingMessage();
        preparator = new TokenbindingMessagePreparator(chooser, message);
        config.setDefaultSelectedSignatureAndHashAlgorithm(new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA,
                HashAlgorithm.SHA256));
        context.setClientRandom(ArrayConverter
                .hexStringToByteArray("772EF595D8B1885E8F5DA5B0595B9E324E04571D5392BF99A046F00A1D331AEB"));
        context.setServerRandom(ArrayConverter
                .hexStringToByteArray("C3CE61F0F6A8335E98AF8725385586B41FEFF205B4E05A000823F78B5F8F5C02"));
        context.setMasterSecret(ArrayConverter
                .hexStringToByteArray("3B4B7628B03375E582E1398DA34FB51A9526847151337029CC15689130EE879B65DC461EF9DAEBB33C4C0FF5885FCE73"));
        context.setSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        context.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * TokenbindingMessagePreparator.
     */
    @Test
    public void testPrepareProtocolMessageContents() throws Exception {
        preparator.prepare();
        Configurator.setRootLevel(Level.ALL);
        Serializer serializer = new TokenBindingMessageSerializer(message, ProtocolVersion.TLS12);
        byte[] serialize = serializer.serialize();
        TokenBindingMessageParser selfParser = new TokenBindingMessageParser(0, serialize, ProtocolVersion.TLS12);
        TokenBindingMessage selfParsed = selfParser.parse();
        assertNotNull(selfParsed);
        String base64 = "AIkAAgBBQM9eQES_uxoyRn0DDoYLcWqvm6Oo3p0lI1s3fRjdIj6dw8wLDf0RWkxuyNAmgAQkUWxm8_JfwS8MziBYVuJ5ECcAQHF_HGcPiSv_X60y5Ql-AxoqaWzwqXvpStEBgY_IX8kT_qAHsb5h38ZuQoWOaZVgqlF1sa70B4GVXxmi2JkdJYcAAA";
        byte[] decode = Base64.getUrlDecoder().decode(base64);
        TokenBindingMessageParser parser = new TokenBindingMessageParser(0, decode, ProtocolVersion.TLS12);
        TokenBindingMessage parsedMessage = parser.parse();
        byte[] xBytes = new byte[32];
        System.arraycopy(parsedMessage.getPoint().getValue(), 0, xBytes, 0, 32);
        System.out.println("X:" + ArrayConverter.bytesToHexString(xBytes));
        byte[] yBytes = new byte[32];
        System.arraycopy(parsedMessage.getPoint().getValue(), 32, yBytes, 0, 32);
        System.out.println("Y:" + ArrayConverter.bytesToHexString(yBytes));
        BigInteger intX = new BigInteger(xBytes);
        System.out.println("intx: " + intX);

        ASN1Integer x = new ASN1Integer(xBytes);
        System.out.println("xasn1:" + x.getPositiveValue());
        ASN1Integer y = new ASN1Integer(yBytes);
        ECDomainParameters generateEcParameters = generateEcParameters();
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(generateEcParameters.getCurve()
                .createPoint(x.getPositiveValue(), y.getPositiveValue()), generateEcParameters);
        System.out.println("RAW X:" + ecPublicKeyParameters.getQ().getRawXCoord().toBigInteger());
        System.out.println("RAW Y:" + ecPublicKeyParameters.getQ().getRawYCoord().toBigInteger());
        System.out.println("Valid: " + ecPublicKeyParameters.getQ().isValid());
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, ecPublicKeyParameters);

        byte[] signedContent = ArrayConverter
                .hexStringToByteArray("0002A5F86D4EA32D7B305774F6EA56DB444F4D70D777ABF77B810561935F3A96B9C2");// Correct
                                                                                                              // ekm
                                                                                                              // with
                                                                                                              // blablub
        // ours byte[] signedContent =
        // ArrayConverter.hexStringToByteArray("00022054736C9903E145286A925F9F2C064603D3211BCF0D81EDB6FEB6E9ACCAB4B7");
        byte[] rBytes = new byte[32];
        System.arraycopy(parsedMessage.getSignature().getValue(), 0, rBytes, 0, 32);
        byte[] sBytes = new byte[32];
        System.arraycopy(parsedMessage.getSignature().getValue(), 32, sBytes, 0, 32);
        System.out.println("r:" + ArrayConverter.bytesToHexString(rBytes));
        System.out.println("s:" + ArrayConverter.bytesToHexString(sBytes));
        System.out.println("r:" + new ASN1Integer(rBytes).getPositiveValue());
        System.out.println("s:" + new ASN1Integer(sBytes).getPositiveValue());
        System.out.println(signer.verifySignature(signedContent, new ASN1Integer(rBytes).getPositiveValue(),
                new ASN1Integer(sBytes).getPositiveValue()));
        // decodeASN1(parsedMessage.getSignature().getValue());
    }

    private ECDomainParameters generateEcParameters() {
        NamedCurve[] curves = new NamedCurve[] { NamedCurve.SECP256R1 };
        ECPointFormat[] formats = new ECPointFormat[] { ECPointFormat.UNCOMPRESSED };
        InputStream is = new ByteArrayInputStream(ArrayConverter.concatenate(
                new byte[] { EllipticCurveType.NAMED_CURVE.getValue() }, NamedCurve.SECP256R1.getValue()));
        ECDomainParameters ecParams;
        try {
            ecParams = ECCUtilsBCWrapper.readECParameters(curves, formats, is);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }

        return ecParams;
    }
}
