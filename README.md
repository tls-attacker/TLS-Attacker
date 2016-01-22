# TLS-Attacker
TLS-Attacker is a Java-based framework for analyzing TLS libraries. It is able to send arbitrary protocol messages in an arbitrary order to the TLS peer, and define their modifications using a provided interface. This gives the developer an oportunity to easily define a custom TLS protocol flow and test it against his TLS library.

## Compilation
In order to compile and use TLS-Attacker, you need to have Java and maven installed. Run the maven command from the TLS-Attacker directory:
```bash
$ cd TLS-Attacker
$ mvn clean package
```
Alternatively, if you are in hurry, you can skip the tests by using:
```bash
$ mvn clean package -DskipTests=true
```
## Code Structure
TLS-Attacker consists of several (maven) projects:
- Utils: contains utilities for Array handling or for deep object copying
- ModifiableVariable: one of the basic modules. It contains modifiable variables that allow one to execute (specific as well as random) variable modifications during the protocol flow. You can for example execute a XOR operation on a byte array, while using this byte array to construct your TLS protocol message. ModifiableVariables are used in the protocol messages.
- TLS: TLS protocol implementation, currently (D)TLS1.2 compatible. 
- Attacks: Implementation of some well-known attacks and tests for these attacks.
- Fuzzer: Fuzzing framework implemented on top of the TLS-Attacker functionality.

![TLS-Attacker design](https://github.com/RUB-NDS/TLS-Attacker-Development/blob/master/resources/design.png)

You can find more information about these modules in the Wiki.

## Usage
In the following, we present some very simple examples on using TLS-Attacker.

If you want to connect to a server, you can use this command:
```bash
$ cd TLS/target
$ java -jar TLS-1.0-SNAPSHOT.jar client -connect localhost:51624 -cipher TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
```
Client-based authentication is also supported, just use it as follows:
```bash
$ java -jar TLS-1.0-SNAPSHOT.jar client -connect localhost:51624 -cipher TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA -keystore ../resources/ec256.jks -password password -alias mykey
```
The Attacks module contains some attacks, you can for example test for the padding oracle vulnerabilities ():
```bash
$ cd Attacks/target
$ java -jar Attacks-1.0-SNAPSHOT-jar-with-dependencies.jar padding_oracle -connect localhost:51624 
```

In case you are a more experienced developer, you can create your own TLS message flow. For example:
```
	TransportHandler transportHandler = initializeTransportHandler(config);
	TlsContext context = initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = initializeWorkflowExecutor(transportHandler, context);
	
	// Setting explicit protocol message workflow
	List<ProtocolMessage> protocolMessages = context.getProtocolMessages();
	protocolMessages.add(new ClientHelloMessage());
	protocolMessages.add(new ServerHelloMessage());
	protocolMessages.add(new CertificateMessage());
	protocolMessages.add(new ServerHelloDoneMessage());
	RSAClientKeyExchangeMessage rsa = new RSAClientKeyExchangeMessage();
	protocolMessages.add(rsa);
	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.CLIENT));
	protocolMessages.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
	protocolMessages.add(new FinishedMessage(ConnectionEnd.SERVER));
	
	// Setting explicit modification of the premaster secret in the ClientKeyExchangeMessage. 
	// EXPLICIT_VALUE presents a padded premaster secret we want to send to the server.
	ModifiableVariable<byte[]> pms = new ModifiableVariable<>();
	pms.setModification(new ExplicitValueModification( EXPLICIT_VALUE ));
	rsa.setPremasterSecret(pms);
	
	// Protocol flow execution
	workflowExecutor.executeWorkflow();
```
You can also use an XML structure a run your customized TLS protocol from XML:
```
tbd
```
You can find further examples in the Wiki.

Attacks: 
- java -jar Attacks-1.0-SNAPSHOT-jar-with-dependencies.jar winshock -connect localhost:51624 -cipher TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA -keystore ../../resources/ec256.jks -password password -alias mykey -signature 0x820428032402403284024032 -signature_length 5000
- java -jar Attacks-1.0-SNAPSHOT-jar-with-dependencies.jar elliptic_test -connect localhost:54433 -named_curve SECP192R1 -public_point_base_x 0x9d42769dfdbe113a851bb6b01b1a515d893b5adbc1f61329 -public_point_base_y 0x74749ac0967a8ff4cc54d93187602dd67eb3d22970aca2ca -premaster_secret 0x9d42769dfdbe113a851bb6b01b1a515d893b5adbc1f61329 -cipher TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
- java -jar Attacks-1.0-SNAPSHOT-jar-with-dependencies.jar bleichenbacher_test -connect localhost:51624

Fuzzer:
- java -jar Fuzzer-1.0-SNAPSHOT-jar-with-dependencies.jar simple_fuzzer -connect localhost:51626 -server_command_file ../resources/command-polarssl -max_fragment_length 4 -heartbeat_mode PEER_ALLOWED_TO_SEND -workflow_trace_type FULL -server_name test.de  -modified_variable_types TLS_CONSTANT,LENGTH,COUNT,PADDING,PUBLIC_KEY,CERTIFICATE -keystore ../resources/keystore-1024.jks -password password -max_transport_response_wait 300 -alias 1024_rsa
