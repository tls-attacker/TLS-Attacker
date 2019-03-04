/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config;

import java.io.File;
import org.junit.Before;
import org.junit.Test;

public class ConfigTest {

    public ConfigTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of createConfig method, of class Config.
     */
    @Test
    public void assertConfigInResourcesIsEqual() {
        ConfigIO.write(new Config(), new File("src/main/resources/default_config.xml"));
    }

    /**
     * Test of createConfig method, of class Config.
     */
    @Test
    public void testCreateConfig_File() {
    }

    /**
     * Test of createConfig method, of class Config.
     */
    @Test
    public void testCreateConfig_InputStream() {
    }

    /**
     * Test of getSessionTicketLifetimeHint method, of class Config.
     */
    @Test
    public void testGetSessionTicketLifetimeHint() {
    }

    /**
     * Test of setSessionTicketLifetimeHint method, of class Config.
     */
    @Test
    public void testSetSessionTicketLifetimeHint() {
    }

    /**
     * Test of getSessionTicketKeyAES method, of class Config.
     */
    @Test
    public void testGetSessionTicketKeyAES() {
    }

    /**
     * Test of setSessionTicketKeyAES method, of class Config.
     */
    @Test
    public void testSetSessionTicketKeyAES() {
    }

    /**
     * Test of getSessionTicketKeyHMAC method, of class Config.
     */
    @Test
    public void testGetSessionTicketKeyHMAC() {
    }

    /**
     * Test of setSessionTicketKeyHMAC method, of class Config.
     */
    @Test
    public void testSetSessionTicketKeyHMAC() {
    }

    /**
     * Test of getSessionTicketKeyName method, of class Config.
     */
    @Test
    public void testGetSessionTicketKeyName() {
    }

    /**
     * Test of setSessionTicketKeyName method, of class Config.
     */
    @Test
    public void testSetSessionTicketKeyName() {
    }

    /**
     * Test of getClientAuthenticationType method, of class Config.
     */
    @Test
    public void testGetClientAuthenticationType() {
    }

    /**
     * Test of setClientAuthenticationType method, of class Config.
     */
    @Test
    public void testSetClientAuthenticationType() {
    }

    /**
     * Test of isHttpsParsingEnabled method, of class Config.
     */
    @Test
    public void testIsHttpsParsingEnabled() {
    }

    /**
     * Test of setHttpsParsingEnabled method, of class Config.
     */
    @Test
    public void testSetHttpsParsingEnabled() {
    }

    /**
     * Test of isUseFreshRandom method, of class Config.
     */
    @Test
    public void testIsUseRandomUnixTime() {
    }

    /**
     * Test of setUseRandomUnixTime method, of class Config.
     */
    @Test
    public void testSetUseRandomUnixTime() {
    }

    /**
     * Test of isUseAllProvidedRecords method, of class Config.
     */
    @Test
    public void testIsUseAllProvidedRecords() {
    }

    /**
     * Test of setUseAllProvidedRecords method, of class Config.
     */
    @Test
    public void testSetUseAllProvidedRecords() {
    }

    /**
     * Test of getDefaultServerRenegotiationInfo method, of class Config.
     */
    @Test
    public void testGetDefaultServerRenegotiationInfo() {
    }

    /**
     * Test of setDefaultServerRenegotiationInfo method, of class Config.
     */
    @Test
    public void testSetDefaultServerRenegotiationInfo() {
    }

    /**
     * Test of getChooserType method, of class Config.
     */
    @Test
    public void testGetChooserType() {
    }

    /**
     * Test of setChooserType method, of class Config.
     */
    @Test
    public void testSetChooserType() {
    }

    /**
     * Test of isEarlyStop method, of class Config.
     */
    @Test
    public void testIsEarlyStop() {
    }

    /**
     * Test of setEarlyStop method, of class Config.
     */
    @Test
    public void testSetEarlyStop() {
    }

    /**
     * Test of getDefaultTokenBindingECPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultTokenBindingECPublicKey() {
    }

    /**
     * Test of setDefaultTokenBindingECPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingECPublicKey() {
    }

    /**
     * Test of getDefaultTokenBindingRsaPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultTokenBindingRsaPublicKey() {
    }

    /**
     * Test of setDefaultTokenBindingRsaPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingRsaPublicKey() {
    }

    /**
     * Test of getDefaultTokenBindingRsaPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultTokenBindingRsaPrivateKey() {
    }

    /**
     * Test of setDefaultTokenBindingRsaPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingRsaPrivateKey() {
    }

    /**
     * Test of getDefaultTokenBindingEcPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultTokenBindingEcPrivateKey() {
    }

    /**
     * Test of setDefaultTokenBindingEcPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingEcPrivateKey() {
    }

    /**
     * Test of getDefaultTokenBindingRsaModulus method, of class Config.
     */
    @Test
    public void testGetDefaultTokenBindingRsaModulus() {
    }

    /**
     * Test of setDefaultTokenBindingRsaModulus method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingRsaModulus() {
    }

    /**
     * Test of getDefaultTokenBindingType method, of class Config.
     */
    @Test
    public void testGetDefaultTokenBindingType() {
    }

    /**
     * Test of setDefaultTokenBindingType method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingType() {
    }

    /**
     * Test of getDefaultRsaCertificate method, of class Config.
     */
    @Test
    public void testGetDefaultRsaCertificate() {
    }

    /**
     * Test of setDefaultRsaCertificate method, of class Config.
     */
    @Test
    public void testSetDefaultRsaCertificate() {
    }

    /**
     * Test of getDefaultDsaCertificate method, of class Config.
     */
    @Test
    public void testGetDefaultDsaCertificate() {
    }

    /**
     * Test of setDefaultDsaCertificate method, of class Config.
     */
    @Test
    public void testSetDefaultDsaCertificate() {
    }

    /**
     * Test of getDefaultEcCertificate method, of class Config.
     */
    @Test
    public void testGetDefaultEcCertificate() {
    }

    /**
     * Test of setDefaultEcCertificate method, of class Config.
     */
    @Test
    public void testSetDefaultEcCertificate() {
    }

    /**
     * Test of getDefaultClientHandshakeTrafficSecret method, of class Config.
     */
    @Test
    public void testGetDefaultClientHandshakeTrafficSecret() {
    }

    /**
     * Test of setDefaultClientHandshakeTrafficSecret method, of class Config.
     */
    @Test
    public void testSetDefaultClientHandshakeTrafficSecret() {
    }

    /**
     * Test of getDefaultServerHandshakeTrafficSecret method, of class Config.
     */
    @Test
    public void testGetDefaultServerHandshakeTrafficSecret() {
    }

    /**
     * Test of setDefaultServerHandshakeTrafficSecret method, of class Config.
     */
    @Test
    public void testSetDefaultServerHandshakeTrafficSecret() {
    }

    /**
     * Test of getDefaultCertificateRequestContext method, of class Config.
     */
    @Test
    public void testGetDefaultCertificateRequestContext() {
    }

    /**
     * Test of setDefaultCertificateRequestContext method, of class Config.
     */
    @Test
    public void testSetDefaultCertificateRequestContext() {
    }

    /**
     * Test of isWorkflowExecutorShouldOpen method, of class Config.
     */
    @Test
    public void testIsWorkflowExecutorShouldOpen() {
    }

    /**
     * Test of setWorkflowExecutorShouldOpen method, of class Config.
     */
    @Test
    public void testSetWorkflowExecutorShouldOpen() {
    }

    /**
     * Test of isWorkflowExecutorShouldClose method, of class Config.
     */
    @Test
    public void testIsWorkflowExecutorShouldClose() {
    }

    /**
     * Test of setWorkflowExecutorShouldClose method, of class Config.
     */
    @Test
    public void testSetWorkflowExecutorShouldClose() {
    }

    /**
     * Test of isStopRecievingAfterFatal method, of class Config.
     */
    @Test
    public void testIsStopRecievingAfterFatal() {
    }

    /**
     * Test of setStopRecievingAfterFatal method, of class Config.
     */
    @Test
    public void testSetStopRecievingAfterFatal() {
    }

    /**
     * Test of getDefaultPSKKey method, of class Config.
     */
    @Test
    public void testGetDefaultPSKKey() {
    }

    /**
     * Test of setDefaultPSKKey method, of class Config.
     */
    @Test
    public void testSetDefaultPSKKey() {
    }

    /**
     * Test of getDefaultPSKIdentity method, of class Config.
     */
    @Test
    public void testGetDefaultPSKIdentity() {
    }

    /**
     * Test of setDefaultPSKIdentity method, of class Config.
     */
    @Test
    public void testSetDefaultPSKIdentity() {
    }

    /**
     * Test of getDefaultPSKIdentityHint method, of class Config.
     */
    @Test
    public void testGetDefaultPSKIdentityHint() {
    }

    /**
     * Test of setDefaultPSKIdentityHint method, of class Config.
     */
    @Test
    public void testSetDefaultPSKIdentityHint() {
    }

    /**
     * Test of getDefaultSRPModulus method, of class Config.
     */
    @Test
    public void testGetDefaultSRPModulus() {
    }

    /**
     * Test of setDefaultSRPModulus method, of class Config.
     */
    @Test
    public void testSetDefaultSRPModulus() {
    }

    /**
     * Test of getDefaultPSKModulus method, of class Config.
     */
    @Test
    public void testGetDefaultPSKModulus() {
    }

    /**
     * Test of setDefaultPSKModulus method, of class Config.
     */
    @Test
    public void testSetDefaultPSKModulus() {
    }

    /**
     * Test of getDefaultPSKServerPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultPSKServerPrivateKey() {
    }

    /**
     * Test of setDefaultPSKServerPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultPSKServerPrivateKey() {
    }

    /**
     * Test of getDefaultPSKServerPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultPSKServerPublicKey() {
    }

    /**
     * Test of setDefaultPSKServerPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultPSKServerPublicKey() {
    }

    /**
     * Test of getDefaultPSKGenerator method, of class Config.
     */
    @Test
    public void testGetDefaultPSKGenerator() {
    }

    /**
     * Test of setDefaultPSKGenerator method, of class Config.
     */
    @Test
    public void testSetDefaultPSKGenerator() {
    }

    /**
     * Test of getDefaultSRPServerPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultSRPServerPrivateKey() {
    }

    /**
     * Test of setDefaultSRPServerPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultSRPServerPrivateKey() {
    }

    /**
     * Test of getDefaultSRPServerPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultSRPServerPublicKey() {
    }

    /**
     * Test of setDefaultSRPServerPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultSRPServerPublicKey() {
    }

    /**
     * Test of getDefaultSRPClientPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultSRPClientPrivateKey() {
    }

    /**
     * Test of setDefaultSRPClientPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultSRPClientPrivateKey() {
    }

    /**
     * Test of getDefaultSRPClientPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultSRPClientPublicKey() {
    }

    /**
     * Test of setDefaultSRPClientPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultSRPClientPublicKey() {
    }

    /**
     * Test of getDefaultSRPGenerator method, of class Config.
     */
    @Test
    public void testGetDefaultSRPGenerator() {
    }

    /**
     * Test of setDefaultSRPGenerator method, of class Config.
     */
    @Test
    public void testSetDefaultSRPGenerator() {
    }

    /**
     * Test of getDefaultSRPServerSalt method, of class Config.
     */
    @Test
    public void testGetDefaultSRPServerSalt() {
    }

    /**
     * Test of setDefaultSRPServerSalt method, of class Config.
     */
    @Test
    public void testSetDefaultSRPServerSalt() {
    }

    /**
     * Test of getDefaultSRPIdentity method, of class Config.
     */
    @Test
    public void testGetDefaultSRPIdentity() {
    }

    /**
     * Test of setDefaultSRPIdentity method, of class Config.
     */
    @Test
    public void testSetDefaultSRPIdentity() {
    }

    /**
     * Test of getDefaultSRPPassword method, of class Config.
     */
    @Test
    public void testGetDefaultSRPPassword() {
    }

    /**
     * Test of setDefaultSRPPassword method, of class Config.
     */
    @Test
    public void testSetDefaultSRPPassword() {
    }

    /**
     * Test of getDefaultClientRSAPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultClientRSAPrivateKey() {
    }

    /**
     * Test of setDefaultClientRSAPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultClientRSAPrivateKey() {
    }

    /**
     * Test of getDefaultServerRSAPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultServerRSAPrivateKey() {
    }

    /**
     * Test of setDefaultServerRSAPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultServerRSAPrivateKey() {
    }

    /**
     * Test of getDefaultServerRSAModulus method, of class Config.
     */
    @Test
    public void testGetDefaultServerRSAModulus() {
    }

    /**
     * Test of setDefaultServerRSAModulus method, of class Config.
     */
    @Test
    public void testSetDefaultServerRSAModulus() {
    }

    /**
     * Test of getDefaultServerRSAPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultServerRSAPublicKey() {
    }

    /**
     * Test of setDefaultServerRSAPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultServerRSAPublicKey() {
    }

    /**
     * Test of getDefaultClientRSAPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultClientRSAPublicKey() {
    }

    /**
     * Test of setDefaultClientRSAPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultClientRSAPublicKey() {
    }

    /**
     * Test of getDefaultServerEcPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultServerEcPrivateKey() {
    }

    /**
     * Test of setDefaultServerEcPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultServerEcPrivateKey() {
    }

    /**
     * Test of getDefaultClientEcPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultClientEcPrivateKey() {
    }

    /**
     * Test of setDefaultClientEcPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultClientEcPrivateKey() {
    }

    /**
     * Test of getDefaultClientEcPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultClientEcPublicKey() {
    }

    /**
     * Test of setDefaultClientEcPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultClientEcPublicKey() {
    }

    /**
     * Test of getDefaultServerEcPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultServerEcPublicKey() {
    }

    /**
     * Test of setDefaultServerEcPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultServerEcPublicKey() {
    }

    /**
     * Test of getDefaultAlertDescription method, of class Config.
     */
    @Test
    public void testGetDefaultAlertDescription() {
    }

    /**
     * Test of setDefaultAlertDescription method, of class Config.
     */
    @Test
    public void testSetDefaultAlertDescription() {
    }

    /**
     * Test of getDefaultAlertLevel method, of class Config.
     */
    @Test
    public void testGetDefaultAlertLevel() {
    }

    /**
     * Test of setDefaultAlertLevel method, of class Config.
     */
    @Test
    public void testSetDefaultAlertLevel() {
    }

    /**
     * Test of getDefaultServerDhPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultServerDhPublicKey() {
    }

    /**
     * Test of setDefaultServerDhPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultServerDhPublicKey() {
    }

    /**
     * Test of getDefaultClientDhPublicKey method, of class Config.
     */
    @Test
    public void testGetDefaultClientDhPublicKey() {
    }

    /**
     * Test of setDefaultClientDhPublicKey method, of class Config.
     */
    @Test
    public void testSetDefaultClientDhPublicKey() {
    }

    /**
     * Test of getDefaultServerDhPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultServerDhPrivateKey() {
    }

    /**
     * Test of setDefaultServerDhPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultServerDhPrivateKey() {
    }

    /**
     * Test of getDefaultServerDsaPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultServerDsaPrivateKey() {
    }

    /**
     * Test of setDefaultServerDsaPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultServerDsaPrivateKey() {
    }

    /**
     * Test of getDefaultPRFAlgorithm method, of class Config.
     */
    @Test
    public void testGetDefaultPRFAlgorithm() {
    }

    /**
     * Test of setDefaultPRFAlgorithm method, of class Config.
     */
    @Test
    public void testSetDefaultPRFAlgorithm() {
    }

    /**
     * Test of getDefaultDtlsCookie method, of class Config.
     */
    @Test
    public void testGetDefaultDtlsCookie() {
    }

    /**
     * Test of setDefaultDtlsCookie method, of class Config.
     */
    @Test
    public void testSetDefaultDtlsCookie() {
    }

    /**
     * Test of getDefaultClientSessionId method, of class Config.
     */
    @Test
    public void testGetDefaultClientSessionId() {
    }

    /**
     * Test of setDefaultClientSessionId method, of class Config.
     */
    @Test
    public void testSetDefaultClientSessionId() {
    }

    /**
     * Test of getDefaultServerSessionId method, of class Config.
     */
    @Test
    public void testGetDefaultServerSessionId() {
    }

    /**
     * Test of setDefaultServerSessionId method, of class Config.
     */
    @Test
    public void testSetDefaultServerSessionId() {
    }

    /**
     * Test of getDefaultSelectedCompressionMethod method, of class Config.
     */
    @Test
    public void testGetDefaultSelectedCompressionMethod() {
    }

    /**
     * Test of setDefaultSelectedCompressionMethod method, of class Config.
     */
    @Test
    public void testSetDefaultSelectedCompressionMethod() {
    }

    /**
     * Test of getDefaultServerRandom method, of class Config.
     */
    @Test
    public void testGetDefaultServerRandom() {
    }

    /**
     * Test of setDefaultServerRandom method, of class Config.
     */
    @Test
    public void testSetDefaultServerRandom() {
    }

    /**
     * Test of getDefaultClientRandom method, of class Config.
     */
    @Test
    public void testGetDefaultClientRandom() {
    }

    /**
     * Test of setDefaultClientRandom method, of class Config.
     */
    @Test
    public void testSetDefaultClientRandom() {
    }

    /**
     * Test of getDefaultPreMasterSecret method, of class Config.
     */
    @Test
    public void testGetDefaultPreMasterSecret() {
    }

    /**
     * Test of setDefaultPreMasterSecret method, of class Config.
     */
    @Test
    public void testSetDefaultPreMasterSecret() {
    }

    /**
     * Test of getDefaultMasterSecret method, of class Config.
     */
    @Test
    public void testGetDefaultMasterSecret() {
    }

    /**
     * Test of setDefaultMasterSecret method, of class Config.
     */
    @Test
    public void testSetDefaultMasterSecret() {
    }

    /**
     * Test of getDefaultHighestClientProtocolVersion method, of class Config.
     */
    @Test
    public void testGetDefaultHighestClientProtocolVersion() {
    }

    /**
     * Test of setDefaultHighestClientProtocolVersion method, of class Config.
     */
    @Test
    public void testSetDefaultHighestClientProtocolVersion() {
    }

    /**
     * Test of getDefaultSelectedProtocolVersion method, of class Config.
     */
    @Test
    public void testGetDefaultSelectedProtocolVersion() {
    }

    /**
     * Test of setDefaultSelectedProtocolVersion method, of class Config.
     */
    @Test
    public void testSetDefaultSelectedProtocolVersion() {
    }

    /**
     * Test of getDefaultServerSupportedSignatureAndHashAlgorithms method, of
     * class Config.
     */
    @Test
    public void testGetDefaultServerSupportedSignatureAndHashAlgorithms() {
    }

    /**
     * Test of setDefaultServerSupportedSignatureAndHashAlgorithms method, of
     * class Config.
     */
    @Test
    public void testSetDefaultServerSupportedSignatureAndHashAlgorithms_List() {
    }

    /**
     * Test of setDefaultServerSupportedSignatureAndHashAlgorithms method, of
     * class Config.
     */
    @Test
    public void testSetDefaultServerSupportedSignatureAndHashAlgorithms_SignatureAndHashAlgorithmArr() {
    }

    /**
     * Test of getDefaultServerSupportedCiphersuites method, of class Config.
     */
    @Test
    public void testGetDefaultServerSupportedCiphersuites() {
    }

    /**
     * Test of setDefaultServerSupportedCiphersuites method, of class Config.
     */
    @Test
    public void testSetDefaultServerSupportedCiphersuites_List() {
    }

    /**
     * Test of setDefaultServerSupportedCiphersuites method, of class Config.
     */
    @Test
    public void testSetDefaultServerSupportedCiphersuites_CipherSuiteArr() {
    }

    /**
     * Test of getDefaultClientSupportedCompressionMethods method, of class
     * Config.
     */
    @Test
    public void testGetDefaultClientSupportedCompressionMethods() {
    }

    /**
     * Test of setDefaultClientSupportedCompressionMethods method, of class
     * Config.
     */
    @Test
    public void testSetDefaultClientSupportedCompressionMethods_List() {
    }

    /**
     * Test of setDefaultClientSupportedCompressionMethods method, of class
     * Config.
     */
    @Test
    public void testSetDefaultClientSupportedCompressionMethods_CompressionMethodArr() {
    }

    /**
     * Test of getDefaultHeartbeatMode method, of class Config.
     */
    @Test
    public void testGetDefaultHeartbeatMode() {
    }

    /**
     * Test of setDefaultHeartbeatMode method, of class Config.
     */
    @Test
    public void testSetDefaultHeartbeatMode() {
    }

    /**
     * Test of getDefaultMaxFragmentLength method, of class Config.
     */
    @Test
    public void testGetDefaultMaxFragmentLength() {
    }

    /**
     * Test of setDefaultMaxFragmentLength method, of class Config.
     */
    @Test
    public void testSetDefaultMaxFragmentLength() {
    }

    /**
     * Test of getDefaultSelectedSignatureAndHashAlgorithm method, of class
     * Config.
     */
    @Test
    public void testGetDefaultSelectedSignatureAndHashAlgorithm() {
    }

    /**
     * Test of setDefaultSelectedSignatureAndHashAlgorithm method, of class
     * Config.
     */
    @Test
    public void testSetDefaultSelectedSignatureAndHashAlgorithm() {
    }

    /**
     * Test of getDefaultClientSupportedPointFormats method, of class Config.
     */
    @Test
    public void testGetDefaultClientSupportedPointFormats() {
    }

    /**
     * Test of setDefaultClientSupportedPointFormats method, of class Config.
     */
    @Test
    public void testSetDefaultClientSupportedPointFormats_List() {
    }

    /**
     * Test of setDefaultClientSupportedPointFormats method, of class Config.
     */
    @Test
    public void testSetDefaultClientSupportedPointFormats_ECPointFormatArr() {
    }

    /**
     * Test of getDefaultLastRecordProtocolVersion method, of class Config.
     */
    @Test
    public void testGetDefaultLastRecordProtocolVersion() {
    }

    /**
     * Test of setDefaultLastRecordProtocolVersion method, of class Config.
     */
    @Test
    public void testSetDefaultLastRecordProtocolVersion() {
    }

    /**
     * Test of getDefaultClientSNIEntryList method, of class Config.
     */
    @Test
    public void testGetDefaultClientSNIEntryList() {
    }

    /**
     * Test of setDefaultClientSNIEntryList method, of class Config.
     */
    @Test
    public void testSetDefaultClientSNIEntryList() {
    }

    /**
     * Test of setDefaultClientSNIEntries method, of class Config.
     */
    @Test
    public void testSetDefaultClientSNIEntries() {
    }

    /**
     * Test of getDefaultClientSupportedSignatureAndHashAlgorithms method, of
     * class Config.
     */
    @Test
    public void testGetDefaultClientSupportedSignatureAndHashAlgorithms() {
    }

    /**
     * Test of setDefaultClientSupportedSignatureAndHashAlgorithms method, of
     * class Config.
     */
    @Test
    public void testSetDefaultClientSupportedSignatureAndHashAlgorithms_List() {
    }

    /**
     * Test of setDefaultClientSupportedSignatureAndHashAlgorithms method, of
     * class Config.
     */
    @Test
    public void testSetDefaultClientSupportedSignatureAndHashAlgorithms_SignatureAndHashAlgorithmArr() {
    }

    /**
     * Test of getDefaultServerSupportedPointFormats method, of class Config.
     */
    @Test
    public void testGetDefaultServerSupportedPointFormats() {
    }

    /**
     * Test of setDefaultServerSupportedPointFormats method, of class Config.
     */
    @Test
    public void testSetDefaultServerSupportedPointFormats_List() {
    }

    /**
     * Test of setDefaultServerSupportedPointFormats method, of class Config.
     */
    @Test
    public void testSetDefaultServerSupportedPointFormats_ECPointFormatArr() {
    }

    /**
     * Test of getDefaultClientNamedGroups method, of class Config.
     */
    @Test
    public void testGetDefaultClientNamedGroups() {
    }

    /**
     * Test of setDefaultClientNamedGroups method, of class Config.
     */
    @Test
    public void testSetDefaultClientNamedGroups_List() {
    }

    /**
     * Test of setDefaultClientNamedGroups method, of class Config.
     */
    @Test
    public void testSetDefaultClientNamedGroups_NamedGroupArr() {
    }

    /**
     * Test of getDefaultServerNamedGroups method, of class Config.
     */
    @Test
    public void testGetDefaultServerNamedGroups() {
    }

    /**
     * Test of setDefaultServerNamedGroups method, of class Config.
     */
    @Test
    public void testSetDefaultServerNamedGroups_List() {
    }

    /**
     * Test of setDefaultServerNamedGroups method, of class Config.
     */
    @Test
    public void testSetDefaultServerNamedGroups_NamedGroupArr() {
    }

    /**
     * Test of getDefaultSelectedCipherSuite method, of class Config.
     */
    @Test
    public void testGetDefaultSelectedCipherSuite() {
    }

    /**
     * Test of setDefaultSelectedCipherSuite method, of class Config.
     */
    @Test
    public void testSetDefaultSelectedCipherSuite() {
    }

    /**
     * Test of isQuickReceive method, of class Config.
     */
    @Test
    public void testIsQuickReceive() {
    }

    /**
     * Test of setQuickReceive method, of class Config.
     */
    @Test
    public void testSetQuickReceive() {
    }

    /**
     * Test of isResetWorkflowtracesBeforeSaving method, of class Config.
     */
    @Test
    public void testIsResetWorkflowtracesBeforeSaving() {
    }

    /**
     * Test of setResetWorkflowtracesBeforeSaving method, of class Config.
     */
    @Test
    public void testSetResetWorkflowtracesBeforeSaving() {
    }

    /**
     * Test of getRecordLayerType method, of class Config.
     */
    @Test
    public void testGetRecordLayerType() {
    }

    /**
     * Test of setRecordLayerType method, of class Config.
     */
    @Test
    public void testSetRecordLayerType() {
    }

    /**
     * Test of isFlushOnMessageTypeChange method, of class Config.
     */
    @Test
    public void testIsFlushOnMessageTypeChange() {
    }

    /**
     * Test of setFlushOnMessageTypeChange method, of class Config.
     */
    @Test
    public void testSetFlushOnMessageTypeChange() {
    }

    /**
     * Test of isCreateRecordsDynamically method, of class Config.
     */
    @Test
    public void testIsCreateRecordsDynamically() {
    }

    /**
     * Test of setCreateRecordsDynamically method, of class Config.
     */
    @Test
    public void testSetCreateRecordsDynamically() {
    }

    /**
     * Test of isCreateIndividualRecords method, of class Config.
     */
    @Test
    public void testIsCreateIndividualRecords() {
    }

    /**
     * Test of setCreateIndividualRecords method, of class Config.
     */
    @Test
    public void testSetCreateIndividualRecords() {
    }

    /**
     * Test of getDefaultMaxRecordData method, of class Config.
     */
    @Test
    public void testGetDefaultMaxRecordData() {
    }

    /**
     * Test of setDefaultMaxRecordData method, of class Config.
     */
    @Test
    public void testSetDefaultMaxRecordData() {
    }

    /**
     * Test of getWorkflowExecutorType method, of class Config.
     */
    @Test
    public void testGetWorkflowExecutorType() {
    }

    /**
     * Test of setWorkflowExecutorType method, of class Config.
     */
    @Test
    public void testSetWorkflowExecutorType() {
    }

    /**
     * Test of getSniType method, of class Config.
     */
    @Test
    public void testGetSniType() {
    }

    /**
     * Test of setSniType method, of class Config.
     */
    @Test
    public void testSetSniType() {
    }

    /**
     * Test of getHeartbeatPayloadLength method, of class Config.
     */
    @Test
    public void testGetHeartbeatPayloadLength() {
    }

    /**
     * Test of setHeartbeatPayloadLength method, of class Config.
     */
    @Test
    public void testSetHeartbeatPayloadLength() {
    }

    /**
     * Test of getHeartbeatPaddingLength method, of class Config.
     */
    @Test
    public void testGetHeartbeatPaddingLength() {
    }

    /**
     * Test of setHeartbeatPaddingLength method, of class Config.
     */
    @Test
    public void testSetHeartbeatPaddingLength() {
    }

    /**
     * Test of isAddPaddingExtension method, of class Config.
     */
    @Test
    public void testIsAddPaddingExtension() {
    }

    /**
     * Test of setAddPaddingExtension method, of class Config.
     */
    @Test
    public void testSetAddPaddingExtension() {
    }

    /**
     * Test of isAddExtendedMasterSecretExtension method, of class Config.
     */
    @Test
    public void testIsAddExtendedMasterSecretExtension() {
    }

    /**
     * Test of setAddExtendedMasterSecretExtension method, of class Config.
     */
    @Test
    public void testSetAddExtendedMasterSecretExtension() {
    }

    /**
     * Test of isAddSessionTicketTLSExtension method, of class Config.
     */
    @Test
    public void testIsAddSessionTicketTLSExtension() {
    }

    /**
     * Test of setAddSessionTicketTLSExtension method, of class Config.
     */
    @Test
    public void testSetAddSessionTicketTLSExtension() {
    }

    /**
     * Test of getDefaultPaddingExtensionBytes method, of class Config.
     */
    @Test
    public void testGetDefaultPaddingExtensionBytes() {
    }

    /**
     * Test of setDefaultPaddingExtensionBytes method, of class Config.
     */
    @Test
    public void testSetDefaultPaddingExtensionBytes() {
    }

    /**
     * Test of getClientCertificateTypes method, of class Config.
     */
    @Test
    public void testGetClientCertificateTypes() {
    }

    /**
     * Test of setClientCertificateTypes method, of class Config.
     */
    @Test
    public void testSetClientCertificateTypes_List() {
    }

    /**
     * Test of setClientCertificateTypes method, of class Config.
     */
    @Test
    public void testSetClientCertificateTypes_ClientCertificateTypeArr() {
    }

    /**
     * Test of isWaitOnlyForExpectedDTLS method, of class Config.
     */
    @Test
    public void testIsWaitOnlyForExpectedDTLS() {
    }

    /**
     * Test of setWaitOnlyForExpectedDTLS method, of class Config.
     */
    @Test
    public void testSetWaitOnlyForExpectedDTLS() {
    }

    /**
     * Test of getDefaultApplicationMessageData method, of class Config.
     */
    @Test
    public void testGetDefaultApplicationMessageData() {
    }

    /**
     * Test of isDoDTLSRetransmits method, of class Config.
     */
    @Test
    public void testIsDoDTLSRetransmits() {
    }

    /**
     * Test of setDoDTLSRetransmits method, of class Config.
     */
    @Test
    public void testSetDoDTLSRetransmits() {
    }

    /**
     * Test of setDefaultApplicationMessageData method, of class Config.
     */
    @Test
    public void testSetDefaultApplicationMessageData() {
    }

    /**
     * Test of isEnforceSettings method, of class Config.
     */
    @Test
    public void testIsEnforceSettings() {
    }

    /**
     * Test of setEnforceSettings method, of class Config.
     */
    @Test
    public void testSetEnforceSettings() {
    }

    /**
     * Test of getDefaultServerDhGenerator method, of class Config.
     */
    @Test
    public void testGetDefaultServerDhGenerator() {
    }

    /**
     * Test of setDefaultServerDhGenerator method, of class Config.
     */
    @Test
    public void testSetDefaultServerDhGenerator() {
    }

    /**
     * Test of getDefaultServerDhModulus method, of class Config.
     */
    @Test
    public void testGetDefaultServerDhModulus() {
    }

    /**
     * Test of setDefaultServerDhModulus method, of class Config.
     */
    @Test
    public void testSetDefaultServerDhModulus() {
    }

    /**
     * Test of getDefaultClientDhPrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultClientDhPrivateKey() {
    }

    /**
     * Test of setDefaultClientDhPrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultClientDhPrivateKey() {
    }

    /**
     * Test of getDistinguishedNames method, of class Config.
     */
    @Test
    public void testGetDistinguishedNames() {
    }

    /**
     * Test of setDistinguishedNames method, of class Config.
     */
    @Test
    public void testSetDistinguishedNames() {
    }

    /**
     * Test of getHighestProtocolVersion method, of class Config.
     */
    @Test
    public void testGetHighestProtocolVersion() {
    }

    /**
     * Test of setHighestProtocolVersion method, of class Config.
     */
    @Test
    public void testSetHighestProtocolVersion() {
    }

    /**
     * Test of isUpdateTimestamps method, of class Config.
     */
    @Test
    public void testIsUpdateTimestamps() {
    }

    /**
     * Test of setUpdateTimestamps method, of class Config.
     */
    @Test
    public void testSetUpdateTimestamps() {
    }

    /**
     * Test of isServerSendsApplicationData method, of class Config.
     */
    @Test
    public void testIsServerSendsApplicationData() {
    }

    /**
     * Test of setServerSendsApplicationData method, of class Config.
     */
    @Test
    public void testSetServerSendsApplicationData() {
    }

    /**
     * Test of getWorkflowTraceType method, of class Config.
     */
    @Test
    public void testGetWorkflowTraceType() {
    }

    /**
     * Test of setWorkflowTraceType method, of class Config.
     */
    @Test
    public void testSetWorkflowTraceType() {
    }

    /**
     * Test of getWorkflowOutput method, of class Config.
     */
    @Test
    public void testGetWorkflowOutput() {
    }

    /**
     * Test of setWorkflowOutput method, of class Config.
     */
    @Test
    public void testSetWorkflowOutput() {
    }

    /**
     * Test of getConfigOutput method, of class Config.
     */
    @Test
    public void testGetConfigOutput() {
    }

    /**
     * Test of setConfigOutput method, of class Config.
     */
    @Test
    public void testSetConfigOutput() {
    }

    /**
     * Test of getWorkflowInput method, of class Config.
     */
    @Test
    public void testGetWorkflowInput() {
    }

    /**
     * Test of setWorkflowInput method, of class Config.
     */
    @Test
    public void testSetWorkflowInput() {
    }

    /**
     * Test of isSniHostnameFatal method, of class Config.
     */
    @Test
    public void testIsSniHostnameFatal() {
    }

    /**
     * Test of setSniHostnameFatal method, of class Config.
     */
    @Test
    public void testSetSniHostnameFatal() {
    }

    /**
     * Test of getMaxFragmentLength method, of class Config.
     */
    @Test
    public void testGetMaxFragmentLength() {
    }

    /**
     * Test of setMaxFragmentLength method, of class Config.
     */
    @Test
    public void testSetMaxFragmentLength() {
    }

    /**
     * Test of getSniHostname method, of class Config.
     */
    @Test
    public void testGetSniHostname() {
    }

    /**
     * Test of setSniHostname method, of class Config.
     */
    @Test
    public void testSetSniHostname() {
    }

    /**
     * Test of getDefaultSelectedNamedGroup method, of class Config.
     */
    @Test
    public void testGetDefaultSelectedNamedGroup() {
    }

    /**
     * Test of setDefaultSelectedNamedGroup method, of class Config.
     */
    @Test
    public void testSetDefaultSelectedNamedGroup() {
    }

    /**
     * Test of isDynamicWorkflow method, of class Config.
     */
    @Test
    public void testIsDynamicWorkflow() {
    }

    /**
     * Test of setDynamicWorkflow method, of class Config.
     */
    @Test
    public void testSetDynamicWorkflow() {
    }

    /**
     * Test of getDefaultClientSupportedCiphersuites method, of class Config.
     */
    @Test
    public void testGetDefaultClientSupportedCiphersuites() {
    }

    /**
     * Test of setDefaultClientSupportedCiphersuites method, of class Config.
     */
    @Test
    public void testSetDefaultClientSupportedCiphersuites_List() {
    }

    /**
     * Test of setDefaultClientSupportedCiphersuites method, of class Config.
     */
    @Test
    public void testSetDefaultClientSupportedCiphersuites_CipherSuiteArr() {
    }

    /**
     * Test of isClientAuthentication method, of class Config.
     */
    @Test
    public void testIsClientAuthentication() {
    }

    /**
     * Test of setClientAuthentication method, of class Config.
     */
    @Test
    public void testSetClientAuthentication() {
    }

    /**
     * Test of getSupportedSignatureAndHashAlgorithms method, of class Config.
     */
    @Test
    public void testGetSupportedSignatureAndHashAlgorithms() {
    }

    /**
     * Test of setSupportedSignatureAndHashAlgorithms method, of class Config.
     */
    @Test
    public void testSetSupportedSignatureAndHashAlgorithms_List() {
    }

    /**
     * Test of setSupportedSignatureAndHashAlgorithms method, of class Config.
     */
    @Test
    public void testSetSupportedSignatureAndHashAlgorithms_SignatureAndHashAlgorithmArr() {
    }

    /**
     * Test of getSupportedVersions method, of class Config.
     */
    @Test
    public void testGetSupportedVersions() {
    }

    /**
     * Test of setSupportedVersions method, of class Config.
     */
    @Test
    public void testSetSupportedVersions_List() {
    }

    /**
     * Test of setSupportedVersions method, of class Config.
     */
    @Test
    public void testSetSupportedVersions_ProtocolVersionArr() {
    }

    /**
     * Test of getHeartbeatMode method, of class Config.
     */
    @Test
    public void testGetHeartbeatMode() {
    }

    /**
     * Test of setHeartbeatMode method, of class Config.
     */
    @Test
    public void testSetHeartbeatMode() {
    }

    /**
     * Test of isAddECPointFormatExtension method, of class Config.
     */
    @Test
    public void testIsAddECPointFormatExtension() {
    }

    /**
     * Test of setAddECPointFormatExtension method, of class Config.
     */
    @Test
    public void testSetAddECPointFormatExtension() {
    }

    /**
     * Test of isAddEllipticCurveExtension method, of class Config.
     */
    @Test
    public void testIsAddEllipticCurveExtension() {
    }

    /**
     * Test of setAddEllipticCurveExtension method, of class Config.
     */
    @Test
    public void testSetAddEllipticCurveExtension() {
    }

    /**
     * Test of isAddHeartbeatExtension method, of class Config.
     */
    @Test
    public void testIsAddHeartbeatExtension() {
    }

    /**
     * Test of setAddHeartbeatExtension method, of class Config.
     */
    @Test
    public void testSetAddHeartbeatExtension() {
    }

    /**
     * Test of isAddMaxFragmentLengthExtenstion method, of class Config.
     */
    @Test
    public void testIsAddMaxFragmentLengthExtenstion() {
    }

    /**
     * Test of setAddMaxFragmentLengthExtenstion method, of class Config.
     */
    @Test
    public void testSetAddMaxFragmentLengthExtenstion() {
    }

    /**
     * Test of isAddServerNameIndicationExtension method, of class Config.
     */
    @Test
    public void testIsAddServerNameIndicationExtension() {
    }

    /**
     * Test of setAddServerNameIndicationExtension method, of class Config.
     */
    @Test
    public void testSetAddServerNameIndicationExtension() {
    }

    /**
     * Test of isAddSignatureAndHashAlgrorithmsExtension method, of class
     * Config.
     */
    @Test
    public void testIsAddSignatureAndHashAlgrorithmsExtension() {
    }

    /**
     * Test of setAddSignatureAndHashAlgrorithmsExtension method, of class
     * Config.
     */
    @Test
    public void testSetAddSignatureAndHashAlgrorithmsExtension() {
    }

    /**
     * Test of isAddSupportedVersionsExtension method, of class Config.
     */
    @Test
    public void testIsAddSupportedVersionsExtension() {
    }

    /**
     * Test of setAddSupportedVersionsExtension method, of class Config.
     */
    @Test
    public void testSetAddSupportedVersionsExtension() {
    }

    /**
     * Test of isAddKeyShareExtension method, of class Config.
     */
    @Test
    public void testIsAddKeyShareExtension() {
    }

    /**
     * Test of setAddKeyShareExtension method, of class Config.
     */
    @Test
    public void testSetAddKeyShareExtension() {
    }

    /**
     * Test of isAddEarlyDataExtension method, of class Config.
     */
    @Test
    public void testIsAddEarlyDataExtension() {
    }

    /**
     * Test of setAddEarlyDataExtension method, of class Config.
     */
    @Test
    public void testSetAddEarlyDataExtension() {
    }

    /**
     * Test of isAddPSKKeyExchangeModesExtension method, of class Config.
     */
    @Test
    public void testIsAddPSKKeyExchangeModesExtension() {
    }

    /**
     * Test of setAddPSKKeyExchangeModesExtension method, of class Config.
     */
    @Test
    public void testSetAddPSKKeyExchangeModesExtension() {
    }

    /**
     * Test of isAddPreSharedKeyExtension method, of class Config.
     */
    @Test
    public void testIsAddPreSharedKeyExtension() {
    }

    /**
     * Test of setAddPreSharedKeyExtension method, of class Config.
     */
    @Test
    public void testSetAddPreSharedKeyExtension() {
    }

    /**
     * Test of setPSKKeyExchangeModes method, of class Config.
     */
    @Test
    public void testSetPSKKeyExchangeModes() {
    }

    /**
     * Test of getPSKKeyExchangeModes method, of class Config.
     */
    @Test
    public void testGetPSKKeyExchangeModes() {
    }

    /**
     * Test of getDefaultDTLSCookieLength method, of class Config.
     */
    @Test
    public void testGetDefaultDTLSCookieLength() {
    }

    /**
     * Test of setDefaultDTLSCookieLength method, of class Config.
     */
    @Test
    public void testSetDefaultDTLSCookieLength() {
    }

    /**
     * Test of getPaddingLength method, of class Config.
     */
    @Test
    public void testGetPaddingLength() {
    }

    /**
     * Test of setPaddingLength method, of class Config.
     */
    @Test
    public void testSetPaddingLength() {
    }

    /**
     * Test of getKeySharePrivate method, of class Config.
     */
    @Test
    public void testGetKeySharePrivate() {
    }

    /**
     * Test of setKeySharePrivate method, of class Config.
     */
    @Test
    public void testSetKeySharePrivate() {
    }

    /**
     * Test of getTlsSessionTicket method, of class Config.
     */
    @Test
    public void testGetTlsSessionTicket() {
    }

    /**
     * Test of setTlsSessionTicket method, of class Config.
     */
    @Test
    public void testSetTlsSessionTicket() {
    }

    /**
     * Test of getDefaultSignedCertificateTimestamp method, of class Config.
     */
    @Test
    public void testGetDefaultSignedCertificateTimestamp() {
    }

    /**
     * Test of setDefaultSignedCertificateTimestamp method, of class Config.
     */
    @Test
    public void testSetDefaultSignedCertificateTimestamp() {
    }

    /**
     * Test of isAddSignedCertificateTimestampExtension method, of class Config.
     */
    @Test
    public void testIsAddSignedCertificateTimestampExtension() {
    }

    /**
     * Test of setAddSignedCertificateTimestampExtension method, of class
     * Config.
     */
    @Test
    public void testSetAddSignedCertificateTimestampExtension() {
    }

    /**
     * Test of getDefaultClientRenegotiationInfo method, of class Config.
     */
    @Test
    public void testGetDefaultClientRenegotiationInfo() {
    }

    /**
     * Test of setDefaultClientRenegotiationInfo method, of class Config.
     */
    @Test
    public void testSetDefaultClientRenegotiationInfo() {
    }

    /**
     * Test of isAddRenegotiationInfoExtension method, of class Config.
     */
    @Test
    public void testIsAddRenegotiationInfoExtension() {
    }

    /**
     * Test of setAddRenegotiationInfoExtension method, of class Config.
     */
    @Test
    public void testSetAddRenegotiationInfoExtension() {
    }

    /**
     * Test of getDefaultTokenBindingVersion method, of class Config.
     */
    @Test
    public void testGetDefaultTokenBindingVersion() {
    }

    /**
     * Test of setDefaultTokenBindingVersion method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingVersion() {
    }

    /**
     * Test of getDefaultTokenBindingKeyParameters method, of class Config.
     */
    @Test
    public void testGetDefaultTokenBindingKeyParameters() {
    }

    /**
     * Test of setDefaultTokenBindingKeyParameters method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingKeyParameters_List() {
    }

    /**
     * Test of setDefaultTokenBindingKeyParameters method, of class Config.
     */
    @Test
    public void testSetDefaultTokenBindingKeyParameters_TokenBindingKeyParametersArr() {
    }

    /**
     * Test of isAddTokenBindingExtension method, of class Config.
     */
    @Test
    public void testIsAddTokenBindingExtension() {
    }

    /**
     * Test of setAddTokenBindingExtension method, of class Config.
     */
    @Test
    public void testSetAddTokenBindingExtension() {
    }

    /**
     * Test of isAddHttpsCookie method, of class Config.
     */
    @Test
    public void testIsAddHttpsCookie() {
    }

    /**
     * Test of setAddHttpsCookie method, of class Config.
     */
    @Test
    public void testSetAddHttpsCookie() {
    }

    /**
     * Test of getDefaultHttpsCookieName method, of class Config.
     */
    @Test
    public void testGetDefaultHttpsCookieName() {
    }

    /**
     * Test of setDefaultHttpsCookieName method, of class Config.
     */
    @Test
    public void testSetDefaultHttpsCookieName() {
    }

    /**
     * Test of getDefaultHttpsCookieValue method, of class Config.
     */
    @Test
    public void testGetDefaultHttpsCookieValue() {
    }

    /**
     * Test of setDefaultHttpsCookieValue method, of class Config.
     */
    @Test
    public void testSetDefaultHttpsCookieValue() {
    }

    /**
     * Test of getCertificateStatusRequestExtensionRequestType method, of class
     * Config.
     */
    @Test
    public void testGetCertificateStatusRequestExtensionRequestType() {
    }

    /**
     * Test of setCertificateStatusRequestExtensionRequestType method, of class
     * Config.
     */
    @Test
    public void testSetCertificateStatusRequestExtensionRequestType() {
    }

    /**
     * Test of getCertificateStatusRequestExtensionResponderIDList method, of
     * class Config.
     */
    @Test
    public void testGetCertificateStatusRequestExtensionResponderIDList() {
    }

    /**
     * Test of setCertificateStatusRequestExtensionResponderIDList method, of
     * class Config.
     */
    @Test
    public void testSetCertificateStatusRequestExtensionResponderIDList() {
    }

    /**
     * Test of getCertificateStatusRequestExtensionRequestExtension method, of
     * class Config.
     */
    @Test
    public void testGetCertificateStatusRequestExtensionRequestExtension() {
    }

    /**
     * Test of setCertificateStatusRequestExtensionRequestExtension method, of
     * class Config.
     */
    @Test
    public void testSetCertificateStatusRequestExtensionRequestExtension() {
    }

    /**
     * Test of getSessionId method, of class Config.
     */
    @Test
    public void testGetSessionId() {
    }

    /**
     * Test of setSessionId method, of class Config.
     */
    @Test
    public void testSetSessionId() {
    }

    /**
     * Test of getSecureRemotePasswordExtensionIdentifier method, of class
     * Config.
     */
    @Test
    public void testGetSecureRemotePasswordExtensionIdentifier() {
    }

    /**
     * Test of setSecureRemotePasswordExtensionIdentifier method, of class
     * Config.
     */
    @Test
    public void testSetSecureRemotePasswordExtensionIdentifier() {
    }

    /**
     * Test of getSecureRealTimeTransportProtocolProtectionProfiles method, of
     * class Config.
     */
    @Test
    public void testGetSecureRealTimeTransportProtocolProtectionProfiles() {
    }

    /**
     * Test of setSecureRealTimeTransportProtocolProtectionProfiles method, of
     * class Config.
     */
    @Test
    public void testSetSecureRealTimeTransportProtocolProtectionProfiles() {
    }

    /**
     * Test of getSecureRealTimeTransportProtocolMasterKeyIdentifier method, of
     * class Config.
     */
    @Test
    public void testGetSecureRealTimeTransportProtocolMasterKeyIdentifier() {
    }

    /**
     * Test of setSecureRealTimeTransportProtocolMasterKeyIdentifier method, of
     * class Config.
     */
    @Test
    public void testSetSecureRealTimeTransportProtocolMasterKeyIdentifier() {
    }

    /**
     * Test of getUserMappingExtensionHintType method, of class Config.
     */
    @Test
    public void testGetUserMappingExtensionHintType() {
    }

    /**
     * Test of setUserMappingExtensionHintType method, of class Config.
     */
    @Test
    public void testSetUserMappingExtensionHintType() {
    }

    /**
     * Test of getCertificateTypeDesiredTypes method, of class Config.
     */
    @Test
    public void testGetCertificateTypeDesiredTypes() {
    }

    /**
     * Test of setCertificateTypeDesiredTypes method, of class Config.
     */
    @Test
    public void testSetCertificateTypeDesiredTypes() {
    }

    /**
     * Test of getClientCertificateTypeDesiredTypes method, of class Config.
     */
    @Test
    public void testGetClientCertificateTypeDesiredTypes() {
    }

    /**
     * Test of setClientCertificateTypeDesiredTypes method, of class Config.
     */
    @Test
    public void testSetClientCertificateTypeDesiredTypes() {
    }

    /**
     * Test of getServerCertificateTypeDesiredTypes method, of class Config.
     */
    @Test
    public void testGetServerCertificateTypeDesiredTypes() {
    }

    /**
     * Test of setServerCertificateTypeDesiredTypes method, of class Config.
     */
    @Test
    public void testSetServerCertificateTypeDesiredTypes() {
    }

    /**
     * Test of getClientAuthzExtensionDataFormat method, of class Config.
     */
    @Test
    public void testGetClientAuthzExtensionDataFormat() {
    }

    /**
     * Test of setClientAuthzExtensionDataFormat method, of class Config.
     */
    @Test
    public void testSetClientAuthzExtensionDataFormat() {
    }

    /**
     * Test of isCertificateTypeExtensionMessageState method, of class Config.
     */
    @Test
    public void testIsCertificateTypeExtensionMessageState() {
    }

    /**
     * Test of setCertificateTypeExtensionMessageState method, of class Config.
     */
    @Test
    public void testSetCertificateTypeExtensionMessageState() {
    }

    /**
     * Test of getServerAuthzExtensionDataFormat method, of class Config.
     */
    @Test
    public void testGetServerAuthzExtensionDataFormat() {
    }

    /**
     * Test of setServerAuthzExtensionDataFormat method, of class Config.
     */
    @Test
    public void testSetServerAuthzExtensionDataFormat() {
    }

    /**
     * Test of getTrustedCaIndicationExtensionAuthorties method, of class
     * Config.
     */
    @Test
    public void testGetTrustedCaIndicationExtensionAuthorties() {
    }

    /**
     * Test of setTrustedCaIndicationExtensionAuthorties method, of class
     * Config.
     */
    @Test
    public void testSetTrustedCaIndicationExtensionAuthorties() {
    }

    /**
     * Test of isClientCertificateTypeExtensionMessageState method, of class
     * Config.
     */
    @Test
    public void testIsClientCertificateTypeExtensionMessageState() {
    }

    /**
     * Test of setClientCertificateTypeExtensionMessageState method, of class
     * Config.
     */
    @Test
    public void testSetClientCertificateTypeExtensionMessageState() {
    }

    /**
     * Test of isCachedInfoExtensionIsClientState method, of class Config.
     */
    @Test
    public void testIsCachedInfoExtensionIsClientState() {
    }

    /**
     * Test of setCachedInfoExtensionIsClientState method, of class Config.
     */
    @Test
    public void testSetCachedInfoExtensionIsClientState() {
    }

    /**
     * Test of getCachedObjectList method, of class Config.
     */
    @Test
    public void testGetCachedObjectList() {
    }

    /**
     * Test of setCachedObjectList method, of class Config.
     */
    @Test
    public void testSetCachedObjectList() {
    }

    /**
     * Test of getStatusRequestV2RequestList method, of class Config.
     */
    @Test
    public void testGetStatusRequestV2RequestList() {
    }

    /**
     * Test of setStatusRequestV2RequestList method, of class Config.
     */
    @Test
    public void testSetStatusRequestV2RequestList() {
    }

    /**
     * Test of isAddCertificateStatusRequestExtension method, of class Config.
     */
    @Test
    public void testIsAddCertificateStatusRequestExtension() {
    }

    /**
     * Test of setAddCertificateStatusRequestExtension method, of class Config.
     */
    @Test
    public void testSetAddCertificateStatusRequestExtension() {
    }

    /**
     * Test of isAddAlpnExtension method, of class Config.
     */
    @Test
    public void testIsAddAlpnExtension() {
    }

    /**
     * Test of setAddAlpnExtension method, of class Config.
     */
    @Test
    public void testSetAddAlpnExtension() {
    }

    /**
     * Test of isAddSRPExtension method, of class Config.
     */
    @Test
    public void testIsAddSRPExtension() {
    }

    /**
     * Test of setAddSRPExtension method, of class Config.
     */
    @Test
    public void testSetAddSRPExtension() {
    }

    /**
     * Test of isAddSRTPExtension method, of class Config.
     */
    @Test
    public void testIsAddSRTPExtension() {
    }

    /**
     * Test of setAddSRTPExtension method, of class Config.
     */
    @Test
    public void testSetAddSRTPExtension() {
    }

    /**
     * Test of isAddTruncatedHmacExtension method, of class Config.
     */
    @Test
    public void testIsAddTruncatedHmacExtension() {
    }

    /**
     * Test of setAddTruncatedHmacExtension method, of class Config.
     */
    @Test
    public void testSetAddTruncatedHmacExtension() {
    }

    /**
     * Test of isAddUserMappingExtension method, of class Config.
     */
    @Test
    public void testIsAddUserMappingExtension() {
    }

    /**
     * Test of setAddUserMappingExtension method, of class Config.
     */
    @Test
    public void testSetAddUserMappingExtension() {
    }

    /**
     * Test of isAddCertificateTypeExtension method, of class Config.
     */
    @Test
    public void testIsAddCertificateTypeExtension() {
    }

    /**
     * Test of setAddCertificateTypeExtension method, of class Config.
     */
    @Test
    public void testSetAddCertificateTypeExtension() {
    }

    /**
     * Test of isAddClientAuthzExtension method, of class Config.
     */
    @Test
    public void testIsAddClientAuthzExtension() {
    }

    /**
     * Test of setAddClientAuthzExtension method, of class Config.
     */
    @Test
    public void testSetAddClientAuthzExtension() {
    }

    /**
     * Test of isAddServerAuthzExtension method, of class Config.
     */
    @Test
    public void testIsAddServerAuthzExtension() {
    }

    /**
     * Test of setAddServerAuthzExtension method, of class Config.
     */
    @Test
    public void testSetAddServerAuthzExtension() {
    }

    /**
     * Test of isAddClientCertificateTypeExtension method, of class Config.
     */
    @Test
    public void testIsAddClientCertificateTypeExtension() {
    }

    /**
     * Test of setAddClientCertificateTypeExtension method, of class Config.
     */
    @Test
    public void testSetAddClientCertificateTypeExtension() {
    }

    /**
     * Test of isAddServerCertificateTypeExtension method, of class Config.
     */
    @Test
    public void testIsAddServerCertificateTypeExtension() {
    }

    /**
     * Test of setAddServerCertificateTypeExtension method, of class Config.
     */
    @Test
    public void testSetAddServerCertificateTypeExtension() {
    }

    /**
     * Test of isAddEncryptThenMacExtension method, of class Config.
     */
    @Test
    public void testIsAddEncryptThenMacExtension() {
    }

    /**
     * Test of setAddEncryptThenMacExtension method, of class Config.
     */
    @Test
    public void testSetAddEncryptThenMacExtension() {
    }

    /**
     * Test of isAddCachedInfoExtension method, of class Config.
     */
    @Test
    public void testIsAddCachedInfoExtension() {
    }

    /**
     * Test of setAddCachedInfoExtension method, of class Config.
     */
    @Test
    public void testSetAddCachedInfoExtension() {
    }

    /**
     * Test of isAddClientCertificateUrlExtension method, of class Config.
     */
    @Test
    public void testIsAddClientCertificateUrlExtension() {
    }

    /**
     * Test of setAddClientCertificateUrlExtension method, of class Config.
     */
    @Test
    public void testSetAddClientCertificateUrlExtension() {
    }

    /**
     * Test of isAddTrustedCaIndicationExtension method, of class Config.
     */
    @Test
    public void testIsAddTrustedCaIndicationExtension() {
    }

    /**
     * Test of setAddTrustedCaIndicationExtension method, of class Config.
     */
    @Test
    public void testSetAddTrustedCaIndicationExtension() {
    }

    /**
     * Test of isAddCertificateStatusRequestV2Extension method, of class Config.
     */
    @Test
    public void testIsAddCertificateStatusRequestV2Extension() {
    }

    /**
     * Test of setAddCertificateStatusRequestV2Extension method, of class
     * Config.
     */
    @Test
    public void testSetAddCertificateStatusRequestV2Extension() {
    }

    /**
     * Test of getDefaultServerSupportedCompressionMethods method, of class
     * Config.
     */
    @Test
    public void testGetDefaultServerSupportedCompressionMethods() {
    }

    /**
     * Test of setDefaultServerSupportedCompressionMethods method, of class
     * Config.
     */
    @Test
    public void testSetDefaultServerSupportedCompressionMethods_List() {
    }

    /**
     * Test of setDefaultServerSupportedCompressionMethods method, of class
     * Config.
     */
    @Test
    public void testSetDefaultServerSupportedCompressionMethods_CompressionMethodArr() {
    }

    /**
     * Test of getDefaultClientConnection method, of class Config.
     */
    @Test
    public void testGetDefaultClientConnection() {
    }

    /**
     * Test of setDefaultClientConnection method, of class Config.
     */
    @Test
    public void testSetDefaultClientConnection() {
    }

    /**
     * Test of getDefaultServerConnection method, of class Config.
     */
    @Test
    public void testGetDefaultServerConnection() {
    }

    /**
     * Test of setDefaultServerConnection method, of class Config.
     */
    @Test
    public void testSetDefaultServerConnection() {
    }

    /**
     * Test of getDefaultRunningMode method, of class Config.
     */
    @Test
    public void testGetDefaulRunningMode() {
    }

    /**
     * Test of setDefaulRunningMode method, of class Config.
     */
    @Test
    public void testSetDefaulRunningMode() {
    }

    /**
     * Test of isStopActionsAfterFatal method, of class Config.
     */
    @Test
    public void testIsStopActionsAfterFatal() {
    }

    /**
     * Test of setStopActionsAfterFatal method, of class Config.
     */
    @Test
    public void testSetStopActionsAfterFatal() {
    }

    /**
     * Test of getOutputFilters method, of class Config.
     */
    @Test
    public void testGetOutputFilters() {
    }

    /**
     * Test of setOutputFilters method, of class Config.
     */
    @Test
    public void testSetOutputFilters() {
    }

    /**
     * Test of isApplyFiltersInPlace method, of class Config.
     */
    @Test
    public void testIsApplyFiltersInPlace() {
    }

    /**
     * Test of setApplyFiltersInPlace method, of class Config.
     */
    @Test
    public void testSetApplyFiltersInPlace() {
    }

    /**
     * Test of isFiltersKeepUserSettings method, of class Config.
     */
    @Test
    public void testIsFiltersKeepUserSettings() {
    }

    /**
     * Test of setFiltersKeepUserSettings method, of class Config.
     */
    @Test
    public void testSetFiltersKeepUserSettings() {
    }

    /**
     * Test of getDefaultClientApplicationTrafficSecret method, of class Config.
     */
    @Test
    public void testGetDefaultClientApplicationTrafficSecret() {
    }

    /**
     * Test of setDefaultClientApplicationTrafficSecret method, of class Config.
     */
    @Test
    public void testSetDefaultClientApplicationTrafficSecret() {
    }

    /**
     * Test of getDefaultServerApplicationTrafficSecret method, of class Config.
     */
    @Test
    public void testGetDefaultServerApplicationTrafficSecret() {
    }

    /**
     * Test of setDefaultServerApplicationTrafficSecret method, of class Config.
     */
    @Test
    public void testSetDefaultServerApplicationTrafficSecret() {
    }

    /**
     * Test of getEarlyData method, of class Config.
     */
    @Test
    public void testGetEarlyData() {
    }

    /**
     * Test of setEarlyData method, of class Config.
     */
    @Test
    public void testSetEarlyData() {
    }

    /**
     * Test of getDefaultPskSets method, of class Config.
     */
    @Test
    public void testGetDefaultPskSets() {
    }

    /**
     * Test of setDefaultPskSets method, of class Config.
     */
    @Test
    public void testSetDefaultPskSets() {
    }

    /**
     * Test of getPsk method, of class Config.
     */
    @Test
    public void testGetPsk() {
    }

    /**
     * Test of setPsk method, of class Config.
     */
    @Test
    public void testSetPsk() {
    }

    /**
     * Test of getDefaultSessionTicketAgeAdd method, of class Config.
     */
    @Test
    public void testGetDefaultSessionTicketAgeAdd() {
    }

    /**
     * Test of setDefaultSessionTicketAgeAdd method, of class Config.
     */
    @Test
    public void testSetDefaultSessionTicketAgeAdd() {
    }

    /**
     * Test of getDefaultSessionTicketNonce method, of class Config.
     */
    @Test
    public void testGetDefaultSessionTicketNonce() {
    }

    /**
     * Test of setDefaultSessionTicketNonce method, of class Config.
     */
    @Test
    public void testSetDefaultSessionTicketNonce() {
    }

    /**
     * Test of getDefaultSessionTicketIdentity method, of class Config.
     */
    @Test
    public void testGetDefaultSessionTicketIdentity() {
    }

    /**
     * Test of setDefaultSessionTicketIdentity method, of class Config.
     */
    @Test
    public void testSetDefaultSessionTicketIdentity() {
    }

    /**
     * Test of getClientEarlyTrafficSecret method, of class Config.
     */
    @Test
    public void testGetClientEarlyTrafficSecret() {
    }

    /**
     * Test of setClientEarlyTrafficSecret method, of class Config.
     */
    @Test
    public void testSetClientEarlyTrafficSecret() {
    }

    /**
     * Test of getEarlySecret method, of class Config.
     */
    @Test
    public void testGetEarlySecret() {
    }

    /**
     * Test of setEarlySecret method, of class Config.
     */
    @Test
    public void testSetEarlySecret() {
    }

    /**
     * Test of getEarlyDataCipherSuite method, of class Config.
     */
    @Test
    public void testGetEarlyDataCipherSuite() {
    }

    /**
     * Test of setEarlyDataCipherSuite method, of class Config.
     */
    @Test
    public void testSetEarlyDataCipherSuite() {
    }

    /**
     * Test of getEarlyDataPsk method, of class Config.
     */
    @Test
    public void testGetEarlyDataPsk() {
    }

    /**
     * Test of setEarlyDataPsk method, of class Config.
     */
    @Test
    public void testSetEarlyDataPsk() {
    }

    /**
     * Test of isUsePsk method, of class Config.
     */
    @Test
    public void testIsUsePsk() {
    }

    /**
     * Test of setUsePsk method, of class Config.
     */
    @Test
    public void testSetUsePsk() {
    }

    /**
     * Test of getAlpnAnnouncedProtocols method, of class Config.
     */
    @Test
    public void testGetAlpnAnnouncedProtocols() {
    }

    /**
     * Test of setAlpnAnnouncedProtocols method, of class Config.
     */
    @Test
    public void testSetAlpnAnnouncedProtocols() {
    }

    /**
     * Test of getDefaultEcCertificateCurve method, of class Config.
     */
    @Test
    public void testGetDefaultEcCertificateCurve() {
    }

    /**
     * Test of setDefaultEcCertificateCurve method, of class Config.
     */
    @Test
    public void testSetDefaultEcCertificateCurve() {
    }

    /**
     * Test of getDefaultClientRSAModulus method, of class Config.
     */
    @Test
    public void testGetDefaultClientRSAModulus() {
    }

    /**
     * Test of setDefaultClientRSAModulus method, of class Config.
     */
    @Test
    public void testSetDefaultClientRSAModulus() {
    }

    /**
     * Test of getDefaultClientDhGenerator method, of class Config.
     */
    @Test
    public void testGetDefaultClientDhGenerator() {
    }

    /**
     * Test of setDefaultClientDhGenerator method, of class Config.
     */
    @Test
    public void testSetDefaultClientDhGenerator() {
    }

    /**
     * Test of getDefaultClientDhModulus method, of class Config.
     */
    @Test
    public void testGetDefaultClientDhModulus() {
    }

    /**
     * Test of setDefaultClientDhModulus method, of class Config.
     */
    @Test
    public void testSetDefaultClientDhModulus() {
    }

    /**
     * Test of getDefaultKeySharePrivateKey method, of class Config.
     */
    @Test
    public void testGetDefaultKeySharePrivateKey() {
    }

    /**
     * Test of setDefaultKeySharePrivateKey method, of class Config.
     */
    @Test
    public void testSetDefaultKeySharePrivateKey() {
    }

    /**
     * Test of getDefaultClientKeyShareEntries method, of class Config.
     */
    @Test
    public void testGetDefaultClientKeyShareEntries() {
    }

    /**
     * Test of setDefaultClientKeyShareEntries method, of class Config.
     */
    @Test
    public void testSetDefaultClientKeyShareEntries() {
    }

    /**
     * Test of getDefaultServerKeyShareEntry method, of class Config.
     */
    @Test
    public void testGetDefaultServerKeyShareEntry() {
    }

    /**
     * Test of setDefaultServerKeyShareEntry method, of class Config.
     */
    @Test
    public void testSetDefaultServerKeyShareEntry() {
    }

}
