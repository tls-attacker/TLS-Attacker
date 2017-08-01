/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.chooser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import  de.rub.nds.tlsattacker.core.constants.NamedCurve;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class DefaultChooserTest {

    private Chooser chooser;
    private TlsContext context;
    private Config config;

    public DefaultChooserTest() {
    }

    @Before
    public void setUp() {
        config = Config.createConfig();
        context = new TlsContext(config);
        chooser = new DefaultChooser(context, config);
    }

    /**
     * Test of getClientSupportedPointFormats method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSupportedPointFormats() {
        List<ECPointFormat> formatList = new LinkedList<>();
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        config.setDefaultClientSupportedPointFormats(formatList);
        assertTrue(config.getDefaultClientSupportedPointFormats().size() == 8);
        assertTrue(chooser.getClientSupportedPointFormats().size() == 8);
        context.setClientPointFormatsList(new LinkedList<ECPointFormat>());
        assertTrue(chooser.getClientSupportedPointFormats().size() == 0);
    }

    /**
     * Test of getSelectedSigHashAlgorithm method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedSigHashAlgorithm() {
        config.setDefaultSelectedSignatureAndHashAlgorithm(new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS,
                HashAlgorithm.NONE));
        assertEquals(config.getDefaultSelectedSignatureAndHashAlgorithm(), new SignatureAndHashAlgorithm(
                SignatureAlgorithm.RSA_PSS, HashAlgorithm.NONE));
        assertEquals(chooser.getSelectedSigHashAlgorithm(), new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA_PSS,
                HashAlgorithm.NONE));
        context.setSelectedSignatureAndHashAlgorithm(new SignatureAndHashAlgorithm(SignatureAlgorithm.ANONYMOUS,
                HashAlgorithm.SHA1));
        assertEquals(chooser.getSelectedSigHashAlgorithm(), new SignatureAndHashAlgorithm(SignatureAlgorithm.ANONYMOUS,
                HashAlgorithm.SHA1));
    }

    /**
     * Test of getClientSupportedNamedCurves method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSupportedNamedCurves() {
        
    }
    /**
     * Test of getServerSupportedPointFormats method, of class DefaultChooser.
     */
    @Test
    public void testGetServerSupportedPointFormats() {
        List<ECPointFormat> formatList = new LinkedList<>();
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        formatList.add(ECPointFormat.UNCOMPRESSED);
        config.setDefaultServerSupportedPointFormats(formatList);
        assertTrue(config.getDefaultServerSupportedPointFormats().size() == 8);
        assertTrue(chooser.getServerSupportedPointFormats().size() == 8);
        context.setServerPointFormatsList(new LinkedList<ECPointFormat>());
        assertTrue(chooser.getServerSupportedPointFormats().size() == 0);
    }

    /**
     * Test of getClientSupportedSignatureAndHashAlgorithms method, of class
     * DefaultChooser.
     */
    @Test
    public void testGetClientSupportedSignatureAndHashAlgorithms() {
    }

    /**
     * Test of getClientSNIEntryList method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSNIEntryList() {
    }

    /**
     * Test of getLastRecordVersion method, of class DefaultChooser.
     */
    @Test
    public void testGetLastRecordVersion() {
    }

    /**
     * Test of getDistinguishedNames method, of class DefaultChooser.
     */
    @Test
    public void testGetDistinguishedNames() {
    }

    /**
     * Test of getClientCertificateTypes method, of class DefaultChooser.
     */
    @Test
    public void testGetClientCertificateTypes() {
    }

    /**
     * Test of getMaxFragmentLength method, of class DefaultChooser.
     */
    @Test
    public void testGetMaxFragmentLength() {
    }

    /**
     * Test of getHeartbeatMode method, of class DefaultChooser.
     */
    @Test
    public void testGetHeartbeatMode() {
    }

    /**
     * Test of isExtendedMasterSecretExtension method, of class DefaultChooser.
     */
    @Test
    public void testIsExtendedMasterSecretExtension() {
    }

    /**
     * Test of getClientSupportedCompressions method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSupportedCompressions() {
    }

    /**
     * Test of getClientSupportedCiphersuites method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSupportedCiphersuites() {
    }

    /**
     * Test of getServerSupportedSignatureAndHashAlgorithms method, of class
     * DefaultChooser.
     */
    @Test
    public void testGetServerSupportedSignatureAndHashAlgorithms() {
    }

    /**
     * Test of getSelectedProtocolVersion method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedProtocolVersion() {
    }

    /**
     * Test of getHighestClientProtocolVersion method, of class DefaultChooser.
     */
    @Test
    public void testGetHighestClientProtocolVersion() {
    }

    /**
     * Test of getTalkingConnectionEnd method, of class DefaultChooser.
     */
    @Test
    public void testGetTalkingConnectionEnd() {
    }

    /**
     * Test of getMasterSecret method, of class DefaultChooser.
     */
    @Test
    public void testGetMasterSecret() {
    }

    /**
     * Test of getSelectedCipherSuite method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedCipherSuite() {
    }

    /**
     * Test of getPreMasterSecret method, of class DefaultChooser.
     */
    @Test
    public void testGetPreMasterSecret() {
    }

    /**
     * Test of getClientRandom method, of class DefaultChooser.
     */
    @Test
    public void testGetClientRandom() {
    }

    /**
     * Test of getServerRandom method, of class DefaultChooser.
     */
    @Test
    public void testGetServerRandom() {
    }

    /**
     * Test of getSelectedCompressionMethod method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedCompressionMethod() {
    }

    /**
     * Test of getClientSessionId method, of class DefaultChooser.
     */
    @Test
    public void testGetClientSessionId() {
    }

    /**
     * Test of getServerSessionId method, of class DefaultChooser.
     */
    @Test
    public void testGetServerSessionId() {
    }

    /**
     * Test of getDtlsCookie method, of class DefaultChooser.
     */
    @Test
    public void testGetDtlsCookie() {
    }

    /**
     * Test of getTransportHandler method, of class DefaultChooser.
     */
    @Test
    public void testGetTransportHandler() {
    }

    /**
     * Test of getPRFAlgorithm method, of class DefaultChooser.
     */
    @Test
    public void testGetPRFAlgorithm() {
    }

    /**
     * Test of getSessionTicketTLS method, of class DefaultChooser.
     */
    @Test
    public void testGetSessionTicketTLS() {
    }

    /**
     * Test of getSignedCertificateTimestamp method, of class DefaultChooser.
     */
    @Test
    public void testGetSignedCertificateTimestamp() {
    }

    /**
     * Test of getRenegotiationInfo method, of class DefaultChooser.
     */
    @Test
    public void testGetRenegotiationInfo() {
    }

    /**
     * Test of getTokenBindingVersion method, of class DefaultChooser.
     */
    @Test
    public void testGetTokenBindingVersion() {
    }

    /**
     * Test of getTokenBindingKeyParameters method, of class DefaultChooser.
     */
    @Test
    public void testGetTokenBindingKeyParameters() {
    }

    /**
     * Test of getDhModulus method, of class DefaultChooser.
     */
    @Test
    public void testGetDhModulus() {
    }

    /**
     * Test of getDhGenerator method, of class DefaultChooser.
     */
    @Test
    public void testGetDhGenerator() {
    }

    /**
     * Test of getDhServerPrivateKey method, of class DefaultChooser.
     */
    @Test
    public void testGetDhServerPrivateKey() {
    }

    /**
     * Test of getDhClientPrivateKey method, of class DefaultChooser.
     */
    @Test
    public void testGetDhClientPrivateKey() {
    }

    /**
     * Test of getDhServerPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetDhServerPublicKey() {
    }

    /**
     * Test of getDhClientPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetDhClientPublicKey() {
    }

    /**
     * Test of getServerEcPrivateKey method, of class DefaultChooser.
     */
    @Test
    public void testGetServerEcPrivateKey() {
    }

    /**
     * Test of getClientEcPrivateKey method, of class DefaultChooser.
     */
    @Test
    public void testGetClientEcPrivateKey() {
    }

    /**
     * Test of getSelectedCurve method, of class DefaultChooser.
     */
    @Test
    public void testGetSelectedCurve() {
    }

    /**
     * Test of getClientEcPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetClientEcPublicKey() {
    }

    /**
     * Test of getServerEcPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetServerEcPublicKey() {
    }

    /**
     * Test of getEcCurveType method, of class DefaultChooser.
     */
    @Test
    public void testGetEcCurveType() {
    }

    /**
     * Test of getRsaModulus method, of class DefaultChooser.
     */
    @Test
    public void testGetRsaModulus() {
    }

    /**
     * Test of getServerRSAPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetServerRSAPublicKey() {
    }

    /**
     * Test of getClientRSAPublicKey method, of class DefaultChooser.
     */
    @Test
    public void testGetClientRSAPublicKey() {
    }

    /**
     * Test of getCertificateRequestContext method, of class DefaultChooser.
     */
    @Test
    public void testGetCertificateRequestContext() {
    }

    /**
     * Test of getServerHandshakeTrafficSecret method, of class DefaultChooser.
     */
    @Test
    public void testGetServerHandshakeTrafficSecret() {
    }

    /**
     * Test of getClientHandshakeTrafficSecret method, of class DefaultChooser.
     */
    @Test
    public void testGetClientHandshakeTrafficSecret() {
    }

}
