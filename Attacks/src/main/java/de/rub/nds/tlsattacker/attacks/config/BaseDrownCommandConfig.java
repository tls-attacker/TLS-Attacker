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
import de.rub.nds.tlsattacker.attacks.config.delegate.AttackDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;

public abstract class BaseDrownCommandConfig extends AttackConfig {

    @ParametersDelegate
    ClientDelegate clientDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    @Parameter(names = "-premasterSecretsFile",
        description = "File containing captured " + "Premaster secrets to be decrypted in hex format, one per line")
    private String premasterSecretsFilePath;

    public BaseDrownCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        attackDelegate = new AttackDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(attackDelegate);
        addDelegate(starttlsDelegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setRecordLayerType(RecordLayerType.BLOB);
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);

        return config;
    }

    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    public String getPremasterSecretsFilePath() {
        return premasterSecretsFilePath;
    }
}
