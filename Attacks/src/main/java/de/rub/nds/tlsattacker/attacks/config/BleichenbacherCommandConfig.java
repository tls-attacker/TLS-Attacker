/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.attacks.config.delegate.AttackDelegate;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class BleichenbacherCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "bleichenbacher";

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;
    @Parameter(names = "-encrypted_premaster_secret", description = "Encrypted premaster secret from the RSA client key "
            + "exchange message. You can retrieve this message from the Wireshark traffic. Find the client key exchange "
            + "message, right click on the \"EncryptedPremaster\" value and copy this value as a Hex Stream.")
    private String encryptedPremasterSecret;
    @Parameter(names = "-type", description = "Type of the Bleichenbacher test. FAST contains only basic server test queries. "
            + "FULL results in a comprehensive server evaluation.")
    private Type type = Type.FAST;
    @Parameter(names = "-msgPkcsConform", description = "Used by the real Bleichenbacher attack. Indicates whether the original "
            + "message that we are going to decrypt is PKCS#1 conform or not (more precisely, whether it starts with 0x00 0x02).", arity = 1)
    private boolean msgPkcsConform = true;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    @Parameter(names = "-workflowType", description = "Which workflow traces should be tested with")
    private BleichenbacherWorkflowType workflowType = BleichenbacherWorkflowType.CKE_CCS_FIN;

    ;

    /**
     *
     * @param delegate
     */
    public BleichenbacherCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        attackDelegate = new AttackDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(attackDelegate);
        addDelegate(starttlsDelegate);
    }

    /**
     *
     * @return
     */
    public Type getType() {
        return type;
    }

    /**
     *
     * @param type
     */
    public void setType(Type type) {
        this.type = type;
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.RSA
                        || AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.PSK_RSA) {
                    cipherSuites.add(suite);
                }
            }
            config.setDefaultClientSupportedCiphersuites(cipherSuites);
        }
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setStopActionsAfterFatal(true);
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(false);
        config.setWorkflowExecutorShouldClose(false);

        return config;
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    /**
     *
     * @return
     */
    public String getEncryptedPremasterSecret() {
        return encryptedPremasterSecret;
    }

    /**
     *
     * @return
     */
    public boolean isMsgPkcsConform() {
        return msgPkcsConform;
    }

    /**
     *
     */
    public enum Type {

        /**
         *
         */
        FULL,
        /**
         *
         */
        FAST
    }

    public BleichenbacherWorkflowType getWorkflowType() {
        return workflowType;
    }

    public void setWorkflowType(BleichenbacherWorkflowType workflowType) {
        this.workflowType = workflowType;
    }
}
