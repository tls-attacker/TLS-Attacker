/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlpnProtocol;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SniType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.util.ArrayList;
import java.util.List;

public class QuicDelegate extends Delegate {
    @Parameter(names = "-quic", description = "Scan QUIC")
    private boolean quic = false;

    public QuicDelegate() {}

    public boolean isQuic() {
        return quic;
    }

    public void setQuic(boolean quic) {
        this.quic = quic;
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        if (quic) {
            config.setQuic(true);

            // Connection
            config.getDefaultClientConnection().setFirstTimeout(5000);
            config.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.UDP);
            config.getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.UDP);

            config.setDefaultLayerConfiguration(LayerConfiguration.QUIC);
            config.setWorkflowExecutorType(WorkflowExecutorType.QUIC);

            // Protocol Version
            config.setHighestProtocolVersion(ProtocolVersion.TLS13);
            config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
            config.setSupportedVersions(ProtocolVersion.TLS13);
            config.setDefaultLastRecordProtocolVersion(ProtocolVersion.TLS13);
            config.setTls13BackwardsCompatibilityMode(false);

            // Cipher Suites and Named Groups
            config.setDefaultClientSupportedCipherSuites(CipherSuite.getTls13CipherSuites());
            config.setDefaultClientNamedGroups(NamedGroup.SECP256R1);
            config.setDefaultServerNamedGroups(NamedGroup.SECP256R1);
            config.setDefaultSelectedNamedGroup(NamedGroup.SECP256R1);
            config.setDefaultClientKeyShareNamedGroups(NamedGroup.SECP256R1);

            // Extensions
            config.setAddServerNameIndicationExtension(true);
            config.setSniType(SniType.HOST_NAME);
            config.setAddECPointFormatExtension(false);
            config.setAddSupportedVersionsExtension(true);
            config.setAddEllipticCurveExtension(true);
            config.setAddSignatureAndHashAlgorithmsExtension(true);
            config.setAddKeyShareExtension(true);
            config.setAddPSKKeyExchangeModesExtension(true);
            config.setAddRenegotiationInfoExtension(false);
            config.setAddAlpnExtension(true);
            config.setQuicTransportParametersExtension(true);
            List<String> alpnEntries = new ArrayList<>();
            alpnEntries.add(AlpnProtocol.HTTP3.getConstant());
            alpnEntries.add("h3-27");
            alpnEntries.add("h3-28");
            alpnEntries.add("h3-29");
            config.setDefaultProposedAlpnProtocols(alpnEntries);
        }
    }
}
