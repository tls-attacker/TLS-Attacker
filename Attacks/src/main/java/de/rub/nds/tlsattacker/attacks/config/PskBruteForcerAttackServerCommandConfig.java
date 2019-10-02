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
import de.rub.nds.tlsattacker.attacks.bruteforce.GuessProviderType;
import de.rub.nds.tlsattacker.attacks.config.delegate.AttackDelegate;
import de.rub.nds.tlsattacker.attacks.exception.WordlistNotFoundException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class PskBruteForcerAttackServerCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "pskbruteforcerserver";

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;

    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;

    @ParametersDelegate
    private AttackDelegate attackDelegate;

    @Parameter(names = "-guessProviderType", description = "Chooses how the BruteForcer will choose the keys to guess")
    private GuessProviderType guessProviderType = GuessProviderType.INCREMENTING;

    @Parameter(names = "-guessProviderInputFile", description = "Set the path to an input file which can be used in the guess provider eg. a path to a wordlist")
    private String guessProviderInputFile = null;

    @Parameter(names = "-clientIdentity", description = "Set a Client Identity")
    private String clientIdentity;

    @Parameter(names = "-pskIdentity", description = "Set the Psk Identity, that should be used")
    private String pskIdentity = "Client_identity";

    /**
     *
     * @param delegate
     */
    public PskBruteForcerAttackServerCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        attackDelegate = new AttackDelegate();
        addDelegate(clientDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(attackDelegate);
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuiteList = new LinkedList<>();
            for (CipherSuite cipherSuite : CipherSuite.getImplemented()) {
                if (cipherSuite.isPsk()) {
                    cipherSuiteList.add(cipherSuite);
                }
            }
            config.setDefaultClientSupportedCiphersuites(cipherSuiteList);
        }
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterFatal(true);
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
    public String getClientIdentity() {
        return clientIdentity;
    }

    /**
     *
     * @return
     */
    public String getPskIdentity() {
        return pskIdentity;
    }

    /**
     *
     * @return
     */
    public String getGuessProviderInputFile() {
        return guessProviderInputFile;
    }

    /**
     *
     * @return
     */
    public InputStream getGuessProviderInputStream() {
        if (this.guessProviderInputFile == null) {
            if (guessProviderType == GuessProviderType.WORDLIST) {
                return (PskBruteForcerAttackClientCommandConfig.class.getClassLoader()
                        .getResourceAsStream("psk_common_passwords.txt"));
            } else {
                return System.in;
            }
        } else {
            File file = new File(getGuessProviderInputFile());
            try {
                return new FileInputStream(file);
            } catch (FileNotFoundException ex) {
                throw new WordlistNotFoundException("Wordlist not found: " + file.getAbsolutePath(), ex);
            }
        }
    }

    /**
     *
     * @return
     */
    public GuessProviderType getGuessProviderType() {
        return guessProviderType;
    }

    /**
     *
     * @param guessProviderType
     */
    public void setGuessProviderType(GuessProviderType guessProviderType) {
        this.guessProviderType = guessProviderType;
    }
}
