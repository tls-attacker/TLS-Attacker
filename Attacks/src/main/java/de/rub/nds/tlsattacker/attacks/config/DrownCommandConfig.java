/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

public class DrownCommandConfig extends AttackConfig {

    public static final String COMMAND = "drown";

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    public DrownCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        addDelegate(clientDelegate);
    }

    @Override
    public boolean isExecuteAttack() {
        return false;
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setRecordLayerType(RecordLayerType.BLOB);
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);
        return config;
    }
}
