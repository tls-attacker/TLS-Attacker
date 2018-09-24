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
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

/**
 *
 */
public class PskBruteForcerAttackClientCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "pskbruteforcerclient";

    @ParametersDelegate
    private ServerDelegate serverDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @Parameter(names = "-guessProviderType", description = "Chooses how the BruteForcer will choose the keys to guess")
    private GuessProviderType guessProviderType = GuessProviderType.INCREMENTING;
    @Parameter(names = "-guessProviderInputFile", description = "Set the path to an input file which can be used in the guess provider eg. a path to a wordlist")
    private String guessProviderInputFile = null;

    /**
     *
     * @param delegate
     */
    public PskBruteForcerAttackClientCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        serverDelegate = new ServerDelegate();
        attackDelegate = new AttackDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        addDelegate(serverDelegate);
        addDelegate(attackDelegate);
        addDelegate(ciphersuiteDelegate);
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setQuickReceive(true);
        config.setEarlyStop(true);

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
