/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class PaddingOracleCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "padding_oracle";

    @Parameter(names = "-recordEngine", description = "The record generator used for the PaddingOracle")
    private PaddingRecordGeneratorType recordGeneratorType = PaddingRecordGeneratorType.SHORT;

    @Parameter(names = "-vectorEngine", description = "The vector generator used for the PaddingOracle")
    private PaddingVectorGeneratorType vectorGeneratorType = PaddingVectorGeneratorType.CLASSIC;

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;

    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;

    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    /**
     * How many rescans should be done
     */
    private int numberOfIterations = 3;

    /**
     *
     * @param delegate
     */
    public PaddingOracleCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        ciphersuiteDelegate = new CipherSuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(starttlsDelegate);
    }

    /**
     *
     * @return
     */
    public PaddingRecordGeneratorType getRecordGeneratorType() {
        return recordGeneratorType;
    }

    /**
     *
     * @param recordGeneratorType
     */
    public void setRecordGeneratorType(PaddingRecordGeneratorType recordGeneratorType) {
        this.recordGeneratorType = recordGeneratorType;
    }

    /**
     *
     * @return
     */
    public PaddingVectorGeneratorType getVectorGeneratorType() {
        return vectorGeneratorType;
    }

    /**
     *
     * @param vectorGeneratorType
     */
    public void setVectorGeneratorType(PaddingVectorGeneratorType vectorGeneratorType) {
        this.vectorGeneratorType = vectorGeneratorType;
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return false;
    }

    @Override
    public Config createConfig() {
        return this.createConfig(super.createConfig());
    }

    /**
     *
     * @param  config
     * @return
     */
    @Override
    public Config createConfig(Config config) {
        super.createConfig(config);
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
            config.setDefaultClientSupportedCipherSuites(cipherSuites);
        }
        for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
            if (!suite.isCBC()) {
                throw new ConfigurationException("This attack only works with CBC Cipher suites");
            }
        }
        config.setQuickReceive(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setStopActionsAfterIOException(true);
        config.setStopActionsAfterFatal(false);
        config.setStopReceivingAfterFatal(false);
        config.setEarlyStop(true);
        config.setWorkflowExecutorShouldClose(false);
        boolean containsEc = false;
        for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
            KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
            if (keyExchangeAlgorithm != null && keyExchangeAlgorithm.name().toUpperCase().contains("EC")) {
                containsEc = true;
                break;
            }
        }
        config.setAddECPointFormatExtension(containsEc);
        config.setAddEllipticCurveExtension(containsEc);

        return config;
    }

    public int getNumberOfIterations() {
        return numberOfIterations;
    }

    public void setNumberOfIterations(int mapListDepth) {
        this.numberOfIterations = mapListDepth;
    }

    public CipherSuiteDelegate getCipherSuiteDelegate() {
        return ciphersuiteDelegate;
    }

    public ProtocolVersionDelegate getProtocolVersionDelegate() {
        return protocolVersionDelegate;
    }
}
