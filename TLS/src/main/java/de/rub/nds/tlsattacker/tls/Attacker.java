/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.tls;

import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <Config>
 */
public abstract class Attacker<Config extends CommandConfig> {

    protected Config config;

    public Attacker(Config config) {
	this.config = config;
    }

    /**
     * Executes a given attack
     * 
     * @param configHandler
     */
    public abstract void executeAttack(ConfigHandler configHandler);

    public Config getConfig() {
	return config;
    }

    public void setConfig(Config config) {
	this.config = config;
    }
}
