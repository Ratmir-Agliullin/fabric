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
            ProposalResponse response = responses.iterator().next();

            System.out.println(response.getMessage().toString());//here
            System.out.println("response, который мы получили = " + response.toString());


            InstantiateProposalRequest instantiateProposalRequest = client.newInstantiationProposalRequest();
            instantiateProposalRequest.setProposalWaitTime(150L);
            instantiateProposalRequest.setChaincodeID(chaincodeID);
            instantiateProposalRequest.setFcn("Init");
          instantiateProposalRequest.setChaincodeEndorsementPolicy(chaincodeEndorsementPolicy);
            instantiateProposalRequest.setArgs(new String[] {"a", "500", "b","200"});
            Map<String, byte[]> tm = new HashMap<>();
            tm.put("HyperLedgerFabric", "InstantiateProposalRequest:JavaSDK".getBytes(UTF_8));
            tm.put("method", "InstantiateProposalRequest".getBytes(UTF_8));
            instantiateProposalRequest.setTransientMap(tm);



            Collection<ProposalResponse> responses4 = channel.sendInstantiationProposal(instantiateProposalRequest);



//
//            List<FabricProposalResponse.Endorsement> ed = new LinkedList<>();
//            FabricProposal.Proposal proposal = null;
//
//            ByteString proposalResponsePayload = ByteString.copyFromUtf8("1234");
//            String proposalTransactionID = "proposalTransactionID";
//
//
//            for (ProposalResponse sdkProposalResponse : responses4) {
//                try {
//                    System.out.println(sdkProposalResponse.getStatus());
//                    System.out.println(sdkProposalResponse.getMessage());
//
//                    FabricProposalResponse.Endorsement element = sdkProposalResponse.getProposalResponse().getEndorsement();
//                    ed.add(element);
//                } catch (NullPointerException e) {
//                    e.printStackTrace();
//                }
//                if (proposal == null) {//here
//                    proposal = sdkProposalResponse.getProposal();
//                    proposalTransactionID = sdkProposalResponse.getTransactionID();
//                    proposalResponsePayload = sdkProposalResponse.getProposalResponse().getPayload();
//
//                }
//
//
//            }
//
//
//            TransactionBuilder transactionBuilder = TransactionBuilder.newBuilder();
//
//            Common.Payload transactionPayload = transactionBuilder
//                    .chaincodeProposal(proposal)
//                    .endorsements(ed)
//                    .proposalResponsePayload(proposalResponsePayload).build();
//
//            Common.Envelope transactionEnvelope = Common.Envelope.newBuilder()
//                    .setPayload(transactionPayload.toByteString())
//                    .setSignature(ByteString.copyFrom(client.getCryptoSuite().sign(org1_user.getEnrollment().getKey(), transactionPayload.toByteArray())))
//                    .build();






            for (ProposalResponse response3 : responses) {
                if ( response3.getStatus() == ProposalResponse.Status.SUCCESS) {
                    System.out.println("Succesful instantiate proposal response Txid: %s from peer %s"+ response.getTransactionID()+ response.getPeer().getName());
                } else {
                    System.out.println("failed instantiate proposal");
                }
            }


            TransactionProposalRequest transactionProposalRequest = client.newTransactionProposalRequest();
            transactionProposalRequest.setChaincodeID(chaincodeID);
            transactionProposalRequest.setFcn("Invoke");
            transactionProposalRequest.setProposalWaitTime(150L);
            transactionProposalRequest.setArgs(new String[] {"move", "a", "b", "100"});

            Map<String, byte[]> tm2 = new HashMap<>();
            tm2.put("HyperLedgerFabric", "TransactionProposalRequest:JavaSDK".getBytes(UTF_8));
            tm2.put("method", "TransactionProposalRequest".getBytes(UTF_8));
            tm2.put("result", ":)".getBytes(UTF_8));  /// This should be returned see chaincode.
            transactionProposalRequest.setTransientMap(tm2);

            System.out.println("sending transactionProposal to all peers with arguments: move(a,b,100)");

            Collection<ProposalResponse> transactionPropResp = channel.sendTransactionProposal(transactionProposalRequest);//, channel.getPeers());
            for (ProposalResponse response1 : transactionPropResp) {
                if (response1.getStatus() == ProposalResponse.Status.SUCCESS) {
                    System.out.println("Successful transaction proposal response Txid: %s from peer %s"+ response1.getTransactionID()+ response1.getPeer().getName());

                } else {
                    System.out.println("failed");
                }
            }



















            QueryByChaincodeRequest queryByChaincodeRequest = client.newQueryProposalRequest();
            queryByChaincodeRequest.setArgs(new String[] {"add", "name1","hash1"});
            queryByChaincodeRequest.setFcn("invoke");
            queryByChaincodeRequest.setChaincodeID(chaincodeID);

            Map<String, byte[]> tm3 = new HashMap<>();
            tm3.put("HyperLedgerFabric", "QueryByChaincodeRequest:JavaSDK".getBytes(UTF_8));
            tm3.put("method", "QueryByChaincodeRequest".getBytes(UTF_8));
            queryByChaincodeRequest.setTransientMap(tm3);

            Collection<ProposalResponse> queryProposals = channel.queryByChaincode(queryByChaincodeRequest, channel.getPeers());
            for (ProposalResponse proposalResponse : queryProposals) {
                if (!proposalResponse.isVerified() || proposalResponse.getStatus() != ProposalResponse.Status.SUCCESS) {
                    System.out.println("Failed query proposal from peer " + proposalResponse.getPeer().getName() + " status: " + proposalResponse.getStatus() +
                            ". Messages: " + proposalResponse.getMessage()
                            + ". Was verified : " + proposalResponse.isVerified());
                } else {
                    String payload = proposalResponse.getProposalResponse().getResponse().getPayload().toStringUtf8();
                    System.out.println("Query payload of b from peer %s returned %s"+ proposalResponse.getPeer().getName()+ payload);

                }
            }


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
