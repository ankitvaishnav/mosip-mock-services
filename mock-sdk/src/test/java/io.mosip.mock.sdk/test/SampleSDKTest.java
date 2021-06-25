package io.mosip.mock.sdk.test;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.biometrics.constant.*;
import io.mosip.kernel.biometrics.entities.*;
import io.mosip.kernel.biometrics.model.Decision;
import io.mosip.kernel.biometrics.model.MatchDecision;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.mock.sdk.impl.SampleSDK;
import io.mosip.mock.sdk.utils.Util;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.*;

import static java.lang.Integer.parseInt;

public class SampleSDKTest {

    Logger LOGGER = LoggerFactory.getLogger(SampleSDKTest.class);

    private String samplePath = "";
    private String sampleIrisNoMatchPath = "";
    private String sampleFullMatchPath = "";
    private String sampleFaceMissing = "";

    @Before
    public void Setup() {
        samplePath = SampleSDKTest.class.getResource("/sample_files/sample.xml").getPath();
        sampleIrisNoMatchPath = SampleSDKTest.class.getResource("/sample_files/sample_iris_no_match.xml").getPath();
        sampleFullMatchPath = SampleSDKTest.class.getResource("/sample_files/sample_full_match.xml").getPath();
        sampleFaceMissing = SampleSDKTest.class.getResource("/sample_files/sample_face_missing.xml").getPath();
    }

    @Test
    public void match_different_iris() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(samplePath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(sampleIrisNoMatchPath);

            gallery[0] = gallery0;

            SampleSDK sampleSDK = new SampleSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            for (int i=0; i< response.getResponse().length; i++){
                Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                Assert.assertEquals(decisions.get(BiometricType.FACE).toString(), decisions.get(BiometricType.FACE).getMatch().toString(), Match.MATCHED.toString());
                Assert.assertEquals(decisions.get(BiometricType.FINGER).toString(), decisions.get(BiometricType.FINGER).getMatch().toString(), Match.MATCHED.toString());
                Assert.assertEquals(decisions.get(BiometricType.IRIS).toString(), decisions.get(BiometricType.IRIS).getMatch().toString(), Match.NOT_MATCHED.toString());
            }
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void match_face_missing() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(samplePath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(sampleFaceMissing);

            gallery[0] = gallery0;

            SampleSDK sampleSDK = new SampleSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            for (int i=0; i< response.getResponse().length; i++){
                Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                Assert.assertEquals(decisions.get(BiometricType.FACE).toString(), decisions.get(BiometricType.FACE).getMatch().toString(), Match.NOT_MATCHED.toString());
                Assert.assertEquals(decisions.get(BiometricType.FINGER).toString(), decisions.get(BiometricType.FINGER).getMatch().toString(), Match.MATCHED.toString());
                Assert.assertEquals(decisions.get(BiometricType.IRIS).toString(), decisions.get(BiometricType.IRIS).getMatch().toString(), Match.MATCHED.toString());
            }
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void printBioRecord() throws JsonProcessingException {
        VersionType v1 = new VersionType(1, 1);
        VersionType cv = new VersionType(1, 1);

        BIRInfo.BIRInfoBuilder birInfoBuilder = new BIRInfo.BIRInfoBuilder();
        birInfoBuilder.withCreator("mosip");
        birInfoBuilder.withIndex("1");
        birInfoBuilder.withCreationDate(LocalDateTime.now());
        birInfoBuilder.withIntegrity(false);
        birInfoBuilder.withNotValidAfter(LocalDateTime.now());
        birInfoBuilder.withNotValidBefore(LocalDateTime.now());
        birInfoBuilder.withPayload("mosip".getBytes());

        BIRInfo birInfo = new BIRInfo(birInfoBuilder);

        BiometricRecord bs = new BiometricRecord(v1, cv, birInfo);

        BIR.BIRBuilder birBuilder = new BIR.BIRBuilder();
        birBuilder.withBdb("mosip.io".getBytes());
        birBuilder.withVersion(v1);
        birBuilder.withCbeffversion(cv);
        birBuilder.withSb("mosip".getBytes());
        birBuilder.withOther("other", "xx");
        birBuilder.withSbInfo(new SBInfo(new SBInfo.SBInfoBuilder().setFormatOwner(new RegistryIDType("mosip", "sbbb"))));

        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withSubtype(new ArrayList(){{add("Left IndexFinger");}});
        bdbInfoBuilder.withType(new ArrayList(){{add("Finger");}});
        bdbInfoBuilder.withLevel(ProcessedLevelType.RAW);
        bdbInfoBuilder.withPurpose(PurposeType.ENROLL);
        bdbInfoBuilder.withIndex("xxxx");
        bdbInfoBuilder.withFormat(new RegistryIDType("mosip", "7"));
        QualityType qualityType = new QualityType();
        qualityType.setAlgorithm(new RegistryIDType("mosip", "SHA-256"));
        qualityType.setScore(Long.valueOf(12));
        bdbInfoBuilder.withQuality(qualityType);

        BDBInfo bdbInfo = new BDBInfo(bdbInfoBuilder);
        birBuilder.withBdbInfo(bdbInfo);
        BIR bir = new BIR(birBuilder);

        bs.getSegments().add(bir);
        ObjectMapper objectMapper = new ObjectMapper();
        String s = objectMapper.writeValueAsString(bs);
        System.out.println(s);
    }

    @Test
    public void print_match_descision() throws JsonProcessingException {
        MatchDecision[] ls = new MatchDecision[2];
        MatchDecision md = new MatchDecision(0);
        md.setAnalyticsInfo(new HashMap<String, String>(){{put("analytics1", "xxxxx");}});

        Decision d1 = new Decision();
        d1.setMatch(Match.MATCHED);
        d1.setAnalyticsInfo(new HashMap<String, String>(){{put("analyticsx", "xxxxx");}});

        Decision d2 = new Decision();
        d2.setMatch(Match.MATCHED);
        d2.setAnalyticsInfo(new HashMap<String, String>(){{put("analyticsx", "xxxxx");}});

        md.getDecisions().put(BiometricType.FINGER, d1);
        md.getDecisions().put(BiometricType.IRIS, d2);

        MatchDecision ms = new MatchDecision(1);

        ms.getDecisions().put(BiometricType.FINGER, d1);
        ms.getDecisions().put(BiometricType.IRIS, d2);

        ls[0] = md;
        ls[1] = ms;
        ObjectMapper objectMapper = new ObjectMapper();
        String s = objectMapper.writeValueAsString(ls);
        System.out.println(s);
    }

    private BiometricRecord xmlFileToBiometricRecord(String path) throws ParserConfigurationException, IOException, SAXException {
        BiometricRecord biometricRecord = new BiometricRecord();
        List bir_segments = new ArrayList();
        File fXmlFile = new File(path);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(fXmlFile);
        doc.getDocumentElement().normalize();
        LOGGER.debug("Root element :" + doc.getDocumentElement().getNodeName());
        Node rootBIRElement = doc.getDocumentElement();
        NodeList childNodes = rootBIRElement.getChildNodes();
        for (int temp = 0; temp < childNodes.getLength(); temp++) {
            Node childNode = childNodes.item(temp);
            if(childNode.getNodeName().equalsIgnoreCase("bir")){
                BIR.BIRBuilder bd = new BIR.BIRBuilder();

                /* Version */
                Node nVersion = ((Element) childNode).getElementsByTagName("Version").item(0);
                String major_version = ((Element) nVersion).getElementsByTagName("Major").item(0).getTextContent();
                String minor_version = ((Element) nVersion).getElementsByTagName("Minor").item(0).getTextContent();
                VersionType bir_version = new VersionType(parseInt(major_version), parseInt(minor_version));
                bd.withVersion(bir_version);

                /* CBEFF Version */
                Node nCBEFFVersion = ((Element) childNode).getElementsByTagName("Version").item(0);
                String cbeff_major_version = ((Element) nCBEFFVersion).getElementsByTagName("Major").item(0).getTextContent();
                String cbeff_minor_version = ((Element) nCBEFFVersion).getElementsByTagName("Minor").item(0).getTextContent();
                VersionType cbeff_bir_version = new VersionType(parseInt(cbeff_major_version), parseInt(cbeff_minor_version));
                bd.withCbeffversion(cbeff_bir_version);

                /* BDB Info */
                Node nBDBInfo = ((Element) childNode).getElementsByTagName("BDBInfo").item(0);
                String bdb_info_type = "";
                String bdb_info_subtype = "";
                NodeList nBDBInfoChilds = nBDBInfo.getChildNodes();
                for (int z=0; z < nBDBInfoChilds.getLength(); z++){
                    Node nBDBInfoChild = nBDBInfoChilds.item(z);
                    if(nBDBInfoChild.getNodeName().equalsIgnoreCase("Type")){
                        bdb_info_type = nBDBInfoChild.getTextContent();
                    }
                    if(nBDBInfoChild.getNodeName().equalsIgnoreCase("Subtype")){
                        bdb_info_subtype = nBDBInfoChild.getTextContent();
                    }
                }

                BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
                bdbInfoBuilder.withType(Arrays.asList(BiometricType.fromValue(bdb_info_type)));
                bdbInfoBuilder.withSubtype(Arrays.asList(bdb_info_subtype));
                BDBInfo bdbInfo = new BDBInfo(bdbInfoBuilder);
                bd.withBdbInfo(bdbInfo);

                /* BDB */
                String nBDB = ((Element) childNode).getElementsByTagName("BDB").item(0).getTextContent();
                bd.withBdb(nBDB.getBytes());

                /* Prepare BIR */
                BIR bir = new BIR(bd);

                /* Add BIR to list of segments */
                bir_segments.add(bir);
            }
        }
        biometricRecord.setSegments(bir_segments);
        return biometricRecord;
    }

}
