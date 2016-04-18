# TLS-Attacker
[![release](https://img.shields.io/badge/Release-v1.0-blue.svg)](https://github.com/RUB-NDS/TLS-Attacker/releases)
![licence](https://img.shields.io/badge/License-Apachev2-brightgreen.svg)

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
- TLS: protocol implementation, currently (D)TLS1.2 compatible. 
- Attacks: Implementation of some well-known attacks and tests for these attacks.
- Fuzzer: Fuzzing framework implemented on top of the TLS-Attacker functionality.

![TLS-Attacker design](https://github.com/RUB-NDS/TLS-Attacker-Development/blob/master/resources/design.png)

You can find more information about these modules in the Wiki.

## Supported Standards and Cipher Suites
Currently, the following features are supported:
- TLS versions 1.0 (RFC-2246), 1.1 (RFC-4346) and 1.2 (RFC-5246)
- DTLS 1.2 (RFC-6347)
- (EC)DH and RSA key exchange algorithms
- AES CBC cipher suites
- Extensions: EC, EC point format, Heartbeat, Max fragment length, Server name, Signature and Hash algorithms
- TLS client (server comming soon)

## Usage
In the following, we present some very simple examples on using TLS-Attacker.

First, you need to start a TLS server. You can use the provided Java server:
```
$ cd TLS-Server
$ java -jar target/TLS-Server-1.0.jar ../resources/rsa1024.jks password TLS 4433
```
...or you can use a different server, e.g. OpenSSL:
```
$ cd resources
$ openssl s_server -key rsa1024key.pem -cert rsa1024cert.pem
```
Both commands start a TLS server on a port 4433.

If you want to connect to a server, you can use this command:
```bash
$ cd Runnable
$ java -jar target/TLS-Attacker-1.0.jar client
```

You can use a different cipher suite, TLS version, or connect to a different port with the following parameters:
```bash
$ java -jar target/TLS-Attacker-1.0.jar client -connect localhost:4433 -cipher TLS_RSA_WITH_AES_256_CBC_SHA -version TLS11
```

Client-based authentication is also supported, just use it as follows. First, start the openssl s_server:
```bash
$ cd resources
$ openssl s_server -key rsa1024key.pem -cert rsa1024cert.pem -verify ec256cert.pem
```

Then start the client with:
```bash
$ java -jar target/TLS-Attacker-1.0.jar client -connect localhost:4433 -cipher TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA -keystore ../resources/ec256.jks -password password -alias alias
```
For more parameters, run:
```bash
$ java -jar target/TLS-Attacker-1.0.jar client -help
```

The Attacks module contains some attacks, you can for example test for the padding oracle vulnerabilities:
```bash
$ cd Attacks/target
$ java -jar target/TLS-Attacker-1.0.jar padding_oracle 
```

In case you are a more experienced developer, you can create your own TLS message flow. For example:
```java
        GeneralConfig generalConfig = new GeneralConfig();
        ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
        configHandler.initialize(generalConfig);

        ClientCommandConfig config = new ClientCommandConfig();
        config.setConnect("localhost:" + PORT);
        config.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);
        
        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	
        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        trace.add(new ServerHelloMessage(ConnectionEnd.SERVER));
        trace.add(new CertificateMessage(ConnectionEnd.SERVER));
        trace.add(new ServerHelloDoneMessage(ConnectionEnd.SERVER));
        trace.add(new RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT));
        trace.add(new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
        trace.add(new FinishedMessage(ConnectionEnd.CLIENT));
        trace.add(new ChangeCipherSpecMessage(ConnectionEnd.SERVER));
        trace.add(new FinishedMessage(ConnectionEnd.SERVER));
        
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
        workflowExecutor.executeWorkflow();

        transportHandler.closeConnection();
```

I know many of you hate Java. Therefore, you can also use an XML structure and run your customized TLS protocol from XML:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workflowTrace>
    <protocolMessages>
        <ClientHello>
            <messageIssuer>CLIENT</messageIssuer>
            <extensions>
                <EllipticCurves>
                    <supportedCurvesConfig>SECP192R1</supportedCurvesConfig>
                    <supportedCurvesConfig>SECP256R1</supportedCurvesConfig>
                    <supportedCurvesConfig>SECP384R1</supportedCurvesConfig>
                    <supportedCurvesConfig>SECP521R1</supportedCurvesConfig>
                </EllipticCurves>
                <ECPointFormat>
                    <pointFormatsConfig>UNCOMPRESSED</pointFormatsConfig>
                </ECPointFormat>
                <SignatureAndHashAlgorithmsExtension>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA512</hashAlgorithm>
                        <signatureAlgorithm>RSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA512</hashAlgorithm>
                        <signatureAlgorithm>ECDSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA256</hashAlgorithm>
                        <signatureAlgorithm>RSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA256</hashAlgorithm>
                        <signatureAlgorithm>ECDSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA1</hashAlgorithm>
                        <signatureAlgorithm>RSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA1</hashAlgorithm>
                        <signatureAlgorithm>ECDSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                </SignatureAndHashAlgorithmsExtension>
            </extensions>
            <supportedCompressionMethods>
                <CompressionMethod>NULL</CompressionMethod>
            </supportedCompressionMethods>
            <supportedCipherSuites>
                <CipherSuite>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256</CipherSuite>
                <CipherSuite>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</CipherSuite>
                <CipherSuite>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</CipherSuite>
            </supportedCipherSuites>
        </ClientHello>
        <ServerHello>
            <messageIssuer>SERVER</messageIssuer>
        </ServerHello>
        <Certificate>
            <messageIssuer>SERVER</messageIssuer>
        </Certificate>
        <ECDHEServerKeyExchange>
            <messageIssuer>SERVER</messageIssuer>
        </ECDHEServerKeyExchange>
        <ServerHelloDone>
            <messageIssuer>SERVER</messageIssuer>
        </ServerHelloDone>
        <ECDHClientKeyExchange>
            <messageIssuer>CLIENT</messageIssuer>
        </ECDHClientKeyExchange>
        <ChangeCipherSpec>
            <messageIssuer>CLIENT</messageIssuer>
        </ChangeCipherSpec>
        <Finished>
            <messageIssuer>CLIENT</messageIssuer>
        </Finished>
        <ChangeCipherSpec>
            <messageIssuer>SERVER</messageIssuer>
        </ChangeCipherSpec>
        <Finished>
            <messageIssuer>SERVER</messageIssuer>
        </Finished>
    </protocolMessages>
</workflowTrace>
```
Given this XML structure is located in config.xml, you would just need to execute:
```bash
$ java -jar target/TLS-Attacker-1.0.jar client -workflow_input config.xml
```


## Modifiable Variables
TLS-Attacker relies on a concept of modifiable variables. Modifiable variables allow one to set modifications to basic types, e.g. Integers, and modify their values by executing the getter methods.

The best way to present the functionality of this concept is by means of a simple example:

```java
ModifiableInteger i = new ModifiableInteger();
i.setOriginalValue(30);
i.setModification(new AddModification(20));
System.out.println(i.getValue());  // 50
```

In this example, we defined a new ModifiableInteger and set its value to 30. Next, we defined a new modification AddModification which simply returns a sum of two integers. We set its value to 20. If we execute the above program, the result 50 is printed. 

We can of course use this concept by constructing our TLS workflows. Imagine you want to test a server for a heartbleed vulnerability. For this purpose, you need to increase the payload length in the heartbeat request. With TLS-Attacker, you can do this as follows:

```xml
<workflowTrace>
    <protocolMessages>
        <ClientHello>
            <messageIssuer>CLIENT</messageIssuer>
            <extensions>
                <EllipticCurves>
                    <supportedCurvesConfig>SECP192R1</supportedCurvesConfig>
                    <supportedCurvesConfig>SECP256R1</supportedCurvesConfig>
                    <supportedCurvesConfig>SECP384R1</supportedCurvesConfig>
                    <supportedCurvesConfig>SECP521R1</supportedCurvesConfig>
                </EllipticCurves>
                <ECPointFormat>
                    <pointFormatsConfig>UNCOMPRESSED</pointFormatsConfig>
                </ECPointFormat>
                <SignatureAndHashAlgorithmsExtension>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA512</hashAlgorithm>
                        <signatureAlgorithm>RSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA512</hashAlgorithm>
                        <signatureAlgorithm>ECDSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA256</hashAlgorithm>
                        <signatureAlgorithm>RSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA256</hashAlgorithm>
                        <signatureAlgorithm>ECDSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA1</hashAlgorithm>
                        <signatureAlgorithm>RSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                    <signatureAndHashAlgorithmsConfig>
                        <hashAlgorithm>SHA1</hashAlgorithm>
                        <signatureAlgorithm>ECDSA</signatureAlgorithm>
                    </signatureAndHashAlgorithmsConfig>
                </SignatureAndHashAlgorithmsExtension>
                <HeartbeatExtension>
                    <heartbeatModeConfig>PEER_ALLOWED_TO_SEND</heartbeatModeConfig>
                </HeartbeatExtension>
            </extensions>
            <supportedCompressionMethods>
                <CompressionMethod>NULL</CompressionMethod>
            </supportedCompressionMethods>
            <supportedCipherSuites>
                <CipherSuite>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256</CipherSuite>
                <CipherSuite>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</CipherSuite>
                <CipherSuite>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</CipherSuite>
            </supportedCipherSuites>
        </ClientHello>
        <ServerHello>
            <messageIssuer>SERVER</messageIssuer>
        </ServerHello>
        <Certificate>
            <messageIssuer>SERVER</messageIssuer>
        </Certificate>
        <ECDHEServerKeyExchange>
            <messageIssuer>SERVER</messageIssuer>
        </ECDHEServerKeyExchange>
        <ServerHelloDone>
            <messageIssuer>SERVER</messageIssuer>
        </ServerHelloDone>
        <ECDHClientKeyExchange>
            <messageIssuer>CLIENT</messageIssuer>
        </ECDHClientKeyExchange>
        <ChangeCipherSpec>
            <messageIssuer>CLIENT</messageIssuer>
        </ChangeCipherSpec>
        <Finished>
            <messageIssuer>CLIENT</messageIssuer>
        </Finished>
        <ChangeCipherSpec>
            <messageIssuer>SERVER</messageIssuer>
        </ChangeCipherSpec>
        <Finished>
            <messageIssuer>SERVER</messageIssuer>
        </Finished>
        <Heartbeat>
            <messageIssuer>CLIENT</messageIssuer>
            <payloadLength>
                <integerAddModification>
                    <summand>2000</summand>
                </integerAddModification>
            </payloadLength>
        </Heartbeat>
        <Heartbeat>
            <messageIssuer>SERVER</messageIssuer>
        </Heartbeat>
    </protocolMessages>
</workflowTrace>
```
As you can see, we explicitly increased the payload length of the Heartbeat message by 2000.

Further examples on attacks and fuzzing are in the Wiki.

## Acknowledgements
The following people have contributed code to the TLS-Attacker Project:
- Florian Pfützenreuter: DTLS 1.2
- Felix Lange: EAP-TLS

Further contributions pull requests are welcome.

## TLS-Attacker Projects
TLS-Attacker has been used in the following scientific papers and projects:
- Tibor Jager, Jörg Schwenk, Juraj Somorovsky. On the Security of TLS 1.3 and QUIC Against Weaknesses in PKCS#1 v1.5 Encryption. CCS'15. https://www.nds.rub.de/research/publications/ccs15/
- Tibor Jager, Jörg Schwenk, Juraj Somorovsky. Practical Invalid Curve Attacks on TLS-ECDH. ESORICS'15. https://www.nds.rub.de/research/publications/ESORICS15/
- Quellcode-basierte Untersuchung von kryptographisch relevanten Aspekten der OpenSSL-Bibliothek. https://www.bsi.bund.de/DE/Publikationen/Studien/OpenSSL-Bibliothek/opensslbibliothek.html

It was furthermore used to discover bugs in various TLS implementations, see the Wiki.

If you have any research ideas or need support by using TLS-Attacker (e.g. you want to include it in your test suite), feel free to contact http://www.hackmanit.de/.

If TLS-Attacker helps you to find a bug in a TLS implementation, please acknowledge this tool. Thank you!
