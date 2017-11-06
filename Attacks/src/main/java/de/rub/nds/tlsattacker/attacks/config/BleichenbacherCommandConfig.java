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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.HostnameExtensionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;

/**
 *

 */
public class BleichenbacherCommandConfig extends AttackConfig {

    public static final String ATTACK_COMMAND = "bleichenbacher";

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;
    @Parameter(names = "-valid_response", description = "Bleichenbacher oracle responds with true if the last server "
            + "message contains this string")
    private String validResponseContent;
    @Parameter(names = "-invalid_response", description = "Bleichenbacher oracle responds with false if the last server "
            + "message contains this string")
    private String invalidResponseContent;
    @Parameter(names = "-encrypted_premaster_secret", description = "Encrypted premaster secret from the RSA client key "
            + "exchange message. You can retrieve this message from the Wireshark traffic. Find the client key exchange "
            + "message, right click on the \"EncryptedPremaster\" value and copy this value as a Hex Stream.")
    private String encryptedPremasterSecret;
    @Parameter(names = "-type", description = "Type of the Bleichenbacher Test results in a different number of server test quries")
    private Type type = Type.FAST;
    @Parameter(names = "-msgPkcsConform", description = "Used by the real Bleichenbacher attack. Indicates whether the original "
            + "message that we are going to decrypt is PKCS#1 conform or not (more precisely, whether it starts with 0x00 0x02.")
    private boolean msgPkcsConform = true;

    public BleichenbacherCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        attackDelegate = new AttackDelegate();
        addDelegate(clientDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(attackDelegate);

        if (delegate.getLogLevel() != Level.ALL && delegate.getLogLevel() != Level.TRACE) {
            Configurator.setAllLevels("de.rub.nds.tlsattacker.core", Level.ERROR);
        }
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
            cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
            config.setDefaultClientSupportedCiphersuites(cipherSuites);
        }
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        return config;
    }

    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    public String getValidResponseContent() {
        return validResponseContent;
    }

    public String getInvalidResponseContent() {
        return invalidResponseContent;
    }

    public String getEncryptedPremasterSecret() {
        return encryptedPremasterSecret;
    }

    public boolean isMsgPkcsConform() {
        return msgPkcsConform;
    }

    public enum Type {

        FULL,
        FAST
    }

}
