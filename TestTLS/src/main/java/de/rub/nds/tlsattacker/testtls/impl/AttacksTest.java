/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.impl;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttack;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttack;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttack;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttack;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttack;
import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.policy.TlsPeerProperties;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.tls.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.tls.config.delegate.Delegate;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class AttacksTest extends TestTLS {

    private final TestServerConfig serverConfig;

    public AttacksTest(TestServerConfig serverConfig) {
        super();
        this.serverConfig = serverConfig;
    }

    @Override
    public void startTests() {
        Attacker attacker;
        String attack;
        result = "\n ";
        BleichenbacherCommandConfig bb = new BleichenbacherCommandConfig(serverConfig.getGeneralDelegate());
        setHost(bb);
        attacker = new BleichenbacherAttack(bb);
        attacker.executeAttack();
        attack = BleichenbacherCommandConfig.ATTACK_COMMAND;
        if (attacker.isVulnerable()) {
            result = result + attack + ": Vulnerable\n ";
        } else {
            result = result + attack + ": Not vulnerable\n ";
        }

        InvalidCurveAttackCommandConfig icea = new InvalidCurveAttackCommandConfig(serverConfig.getGeneralDelegate());
        setHost(icea);
        attacker = new InvalidCurveAttack(icea);
        attacker.executeAttack();
        attack = InvalidCurveAttackCommandConfig.ATTACK_COMMAND;
        if (attacker.isVulnerable()) {
            result = result + attack + ": Vulnerable\n ";
        } else {
            result = result + attack + ": Not vulnerable\n ";
        }

        HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig(serverConfig.getGeneralDelegate());
        setHost(heartbleed);
        attacker = new HeartbleedAttack(heartbleed);
        attacker.executeAttack();
        attack = HeartbleedCommandConfig.ATTACK_COMMAND;
        if (attacker.isVulnerable()) {
            result = result + attack + ": (Probably) Vulnerable\n ";
        } else {
            result = result + attack + ": Not vulnerable\n ";
        }

        PoodleCommandConfig poodle = new PoodleCommandConfig(serverConfig.getGeneralDelegate());
        setHost(poodle);
        attacker = new PoodleAttack(poodle);
        attacker.executeAttack();
        attack = PoodleCommandConfig.ATTACK_COMMAND;
        if (attacker.isVulnerable()) {
            result = result + attack + ": (Probably) Vulnerable\n ";
        } else {
            result = result + attack + ": Not vulnerable\n ";
        }

        PaddingOracleCommandConfig po = new PaddingOracleCommandConfig(serverConfig.getGeneralDelegate());
        setHost(po);
        attacker = new PaddingOracleAttack(po);
        attacker.executeAttack();
        attack = PaddingOracleCommandConfig.ATTACK_COMMAND;
        if (attacker.isVulnerable()) {
            result = result + attack + ": (Probably) Vulnerable\n ";
        } else {
            result = result + attack + ": Not vulnerable\n ";
        }
    }

    public void setHost(TLSDelegateConfig delegateConfig) {
        String host = null;
        for (Delegate delegate : serverConfig.getDelegateList()) {
            if (delegate instanceof ClientDelegate) {
                host = ((ClientDelegate) delegate).getHost();
            }
        }
        for (Delegate delegate : delegateConfig.getDelegateList()) {
            if (delegate instanceof ClientDelegate) {
                ((ClientDelegate) delegate).setHost(host);
                return;
            }
        }
        throw new IllegalArgumentException("Provided Config did not contain ClientDelegate");
    }

    @Override
    public void fillTlsPeerProperties(TlsPeerProperties properties) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

}
