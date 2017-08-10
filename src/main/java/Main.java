import com.google.protobuf.ByteString;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.peer.EndorserGrpc;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.TransactionEventException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.transaction.TransactionBuilder;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.RegistrationException;

import java.io.*;
import java.net.MalformedURLException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Created by user on 21.07.2017.
 */
public class Main {
    public static final String IP = "192.168.99.100";
    public static final String CFPATH = "src/main/env/channel/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem";
    public static final String SERTIFICATEPATH = "src/main/env/channel/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/Admin@org1.example.com-cert.pem";
    public static final String PRIVATKEY = "src/main/env/channel/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/db92ba8af79da54b38bb06b114f1831cce020c15b4f630b30a4505f21ed8b344_sk";
    public static final String SERVERCRT = "src/main/env/channel/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt";
    public static final String PEERSERVER = "src/main/env/channel/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt";
    public static final String CHANELTX = "src/main/env/channel/channel.tx";
    public static final String ADMINSECRET = "adminpw";
    public static final String MSPID = "Org1MSP";
    public static final String CHAIN_CODE_PATH = "mainjava";
    public static final String CHAIN_CODE_VERSION = "1";
    public static final String CHAIN_CODE_NAME = "doc_cc";

    public static void main(String[] args) {
        try {
            File cf = new File(CFPATH);
            Properties properties = new Properties();
            properties.setProperty("allowAllHostNames", "true");
            properties.setProperty("pemFile", cf.getAbsolutePath());

            HFCAClient org1_ca = HFCAClient.createNewInstance("http://" + IP + ":7054", properties);
            org1_ca.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());

            FCUser org1_admin = new FCUser("admin");
            org1_admin.setEnrollment(org1_ca.enroll(org1_admin.getName(), ADMINSECRET));
            FCUser org1_user;
try {
    org1_user = RegisterUser.registerUser("user1", org1_admin, org1_ca, MSPID);
} catch (RegistrationException e){
    System.out.println(e.getMessage());
    System.out.println("Перезапусти докер");
    return;
}

            //    RegisterUser.registerUser("Ratmir", org1_admin, org1_ca, MSPID);

            FCUser org1_peer_admin = new FCUser("Org1Admin");
            org1_peer_admin.setMspId(MSPID);

            File certificateFile = Paths.get(SERTIFICATEPATH).toFile();
            String certificate = new String(IOUtils.toByteArray(new FileInputStream(certificateFile.getAbsolutePath())), "UTF-8");

            File privateKeyFile = Paths.get(PRIVATKEY).toFile();
            PrivateKey privateKey = getPrivateKeyFromBytes(IOUtils.toByteArray(new FileInputStream(privateKeyFile.getAbsolutePath())));

            org1_peer_admin.setEnrollment(new FCEnrollment(privateKey, certificate));

            HFClient client = HFClient.createNewInstance();
            client.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
            client.setUserContext(org1_peer_admin);

            cf = new File(SERVERCRT);
            Properties ordererProperties = new Properties();
            ordererProperties.setProperty("pemFile", cf.getAbsolutePath());
            ordererProperties.setProperty("hostnameOverride", "orderer.example.com");
            ordererProperties.setProperty("sslProvider", "openSSL");
            ordererProperties.setProperty("negotiationType", "TLS");
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{150L, TimeUnit.MINUTES});
            ordererProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{150L, TimeUnit.SECONDS});
            Orderer orderer = client.newOrderer("orderer.example.com", "grpc://" + IP + ":7050", ordererProperties);

            Properties peerProperties = new Properties();
            cf = new File(PEERSERVER);
            peerProperties.setProperty("pemFile", cf.getAbsolutePath());
            peerProperties.setProperty("peerOrg1.mspid", "Org1MSP");
            peerProperties.setProperty("hostnameOverride", "peer0.org1.example.com");
            peerProperties.setProperty("sslProvider", "openSSL");
            peerProperties.setProperty("negotiationType", "TLS");
            peerProperties.put("grpc.NettyChannelBuilderOption.maxInboundMessageSize", 9000000);
            Peer peer = client.newPeer("peer0.org1.example.com", "grpc://" + IP + ":7051", peerProperties);




            Properties ehProperties = new Properties();
            cf = new File(PEERSERVER);
            ehProperties.setProperty("pemFile", cf.getAbsolutePath());
            ehProperties.setProperty("hostnameOverride", "peer0.org1.example.com");
            ehProperties.setProperty("sslProvider", "openSSL");
            ehProperties.setProperty("negotiationType", "TLS");
            ehProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{150L, TimeUnit.MINUTES});
            ehProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{150L, TimeUnit.SECONDS});
            EventHub eventHub = client.newEventHub("peer0.org1.example.com", "grpc://" + IP + ":7053", ehProperties);

            ChannelConfiguration channelConfiguration = new ChannelConfiguration(new File(CHANELTX));
            Channel channel = client.newChannel("mychannel", orderer, channelConfiguration, client.getChannelConfigurationSignature(channelConfiguration, org1_peer_admin));

            channel.addOrderer(orderer);
            channel.joinPeer(peer);
            channel.addEventHub(eventHub);

            channel.initialize();
            System.out.println(channel.getName() + " created!");

//start here

            final ChaincodeID chaincodeID = ChaincodeID.newBuilder().setName(CHAIN_CODE_NAME)
                    .setVersion(CHAIN_CODE_VERSION)
                    .setPath("main/cc/src/doc_cc").build();


            InstallProposalRequest installProposalRequest = client.newInstallProposalRequest();
            installProposalRequest.setChaincodeID(chaincodeID);
           ChaincodeEndorsementPolicy chaincodeEndorsementPolicy = new ChaincodeEndorsementPolicy();
            chaincodeEndorsementPolicy.fromYamlFile(new File("C:\\Users\\agliullin\\IdeaProjects\\fabric6\\src\\main\\env\\chaincodeendorsementpolicy.yaml"));
            File initialFile = new File("C:\\Users\\agliullin\\IdeaProjects\\fabric6");

            installProposalRequest.setChaincodeSourceLocation(initialFile);
        installProposalRequest.setChaincodeVersion(CHAIN_CODE_VERSION);
          //  installProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);

            Set<Peer> peersFromOrg = new HashSet<>();
            peersFromOrg.add(peer);
         //   client.sendInstallProposal(installProposalRequest, peersFromOrg);



            Collection<ProposalResponse> responses = client.sendInstallProposal(installProposalRequest, peersFromOrg);
            for (ProposalResponse sdkProposalResponse : responses) {
                try {
                    System.out.println(sdkProposalResponse.getStatus());
                    System.out.println(sdkProposalResponse.getMessage());

                    //FabricProposalResponse.Endorsement element = sdkProposalResponse.getProposalResponse().getEndorsement();
                    //ed.add(element);
                } catch (NullPointerException e) {
                    e.printStackTrace();
                }
//                if (proposal == null) {
//                    proposal = sdkProposalResponse.getProposal();
//                    proposalTransactionID = sdkProposalResponse.getTransactionID();
//                    proposalResponsePayload = sdkProposalResponse.getProposalResponse().getPayload();
//
//                }


            }

            SDKUtils.getProposalConsistencySets(responses);


            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setProposalWaitTime(120000);
            instantiateProposalRequest.setChaincodeID(chaincodeID);
            instantiateProposalRequest.setFcn("Init");
          instantiateProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
            instantiateProposalRequest.setArgs(new String[] {"a", "500", "b","200"});
            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequest.setTransientMap(tm);



            responses = channel.sendInstantiationProposal(instantiateProposalRequest, channel.getPeers());


            Collection<ProposalResponse> successful = new LinkedList<>();

            for (ProposalResponse response : responses) {
                if (response.isVerified() && response.getStatus() == ProposalResponse.Status.SUCCESS) {
                    successful.add(response);
                }

                System.out.println(response.getStatus());
                System.out.println(response.getMessage());
            }


            Collection<Orderer> orderers = channel.getOrderers();
            channel.sendTransaction(successful, orderers).thenApply(transactionEvent -> {


                //transactionEvent.isValid(); // must be valid to be here.

                try {
                    successful.clear();

                    client.setUserContext(org1_user);

                    ///////////////
                    /// Send transaction proposal to all peers
                    TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
                    transactionProposalRequest.setChaincodeID(chaincodeID);
                    transactionProposalRequest.setFcn("add");
                    transactionProposalRequest.setProposalWaitTime(120000);
                    transactionProposalRequest.setArgs(new String[] {"doc0", "hash0"});

                    Map<String, byte[]> tm2 = new HashMap<>();
                    tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8));
                    tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8));
                    tm2.put("result", ":)".getBytes(UTF_8));  /// This should be returned see chaincode.
                    transactionProposalRequest.setTransientMap(tm2);

                    Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposal(transactionProposalRequest, channel.getPeers());
                    for (ProposalResponse response5 : transactionPropResp) {
                        if (response5.getStatus() == ProposalResponse.Status.SUCCESS) {
                            successful.add(response5);
                        }
                    }


                    Collection<Set<ProposalResponse>> proposalConsistencySets = SDKUtils.getProposalConsistencySets(transactionPropResp);
                    if (proposalConsistencySets.size() != 1) {
                        System.out.println("Expected only one set of consistent proposal responses but got %d"+ proposalConsistencySets.size());
                    }


                    ProposalResponse resp = transactionPropResp.iterator().next();
                    byte[] x = resp.getChaincodeActionResponsePayload(); // This is the data returned by the chaincode.
                    String resultAsString = null;
                    if (x != null) {
                        resultAsString = new String(x, "UTF-8");
                    }
                    System.out.println(resp.getChaincodeActionResponseStatus() + ": " + resultAsString);

                    TxReadWriteSetInfo readWriteSetInfo = resp.getChaincodeActionResponseReadWriteSetInfo();


                    ChaincodeID cid = resp.getChaincodeID();

                    return channel.sendTransaction(successful).get(120, TimeUnit.SECONDS);

                } catch (Exception e) {
                    e.printStackTrace();
                }

                return null;

            }).exceptionally(e -> {
                if (e instanceof TransactionEventException) {
                    BlockEvent.TransactionEvent te = ((TransactionEventException) e).getTransactionEvent();
                    if (te != null) {
                        System.out.println("Transaction with txid %s failed. %s"+ te.getTransactionID()+ e.getMessage());
                    }
                }
                System.out.println("Test failed with %s exception %s"+ e.getClass().getName()+ e.getMessage());

                return null;
            }).get(120, TimeUnit.SECONDS);



            // Close channel
            channel.shutdown(true);
// end here




        } catch (CryptoException e) {
            e.printStackTrace();
        } catch (InvalidArgumentException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (EnrollmentException e) {
            e.printStackTrace();
        } catch (org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static PrivateKey getPrivateKeyFromBytes(byte[] data) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Reader pemReader = new StringReader(new String(data));

        final PrivateKeyInfo pemPair;
        try (PEMParser pemParser = new PEMParser(pemReader)) {
            pemPair = (PrivateKeyInfo) pemParser.readObject();
        }

        PrivateKey privateKey = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getPrivateKey(pemPair);

        return privateKey;
    }

}
