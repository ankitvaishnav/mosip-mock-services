package io.mosip.mock.sdk.utils;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.awt.*;
import java.awt.datatransfer.MimeTypeParseException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Map;

public class Util {

    public static boolean compareHash(byte[] s1, byte[] s2) throws NoSuchAlgorithmException {
        String checksum1 = computeFingerPrint(s1, null).toLowerCase();
        String checksum2 = computeFingerPrint(s2, null).toLowerCase();
        return checksum1.equals(checksum2);
    }

    public static String computeFingerPrint(byte[] data, String metaData) throws NoSuchAlgorithmException {
        byte[] combinedPlainTextBytes = null;
        if (metaData == null) {
            combinedPlainTextBytes = ArrayUtils.addAll(data);
        } else {
            combinedPlainTextBytes = ArrayUtils.addAll(data, metaData.getBytes());
        }
        return DigestUtils.sha256Hex(combinedPlainTextBytes);
    }

    public static ResponseEntity<?> restRequest(String url, HttpMethod httpMethodType, MediaType mediaType, Object body,
                                             Map<String, String> headersMap, Class<?> responseClass) {
        ResponseEntity<?> response = null;
        RestTemplate restTemplate = new RestTemplate();
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(mediaType);
            HttpEntity<?> request = null;
            if (headersMap != null) {
                headersMap.forEach((k, v) -> headers.add(k, v));
            }
            if (body != null) {
                request = new HttpEntity<>(body, headers);
            } else {
                request = new HttpEntity<>(headers);
            }
            response = restTemplate.exchange(url, httpMethodType, request, responseClass);
        } catch (RestClientException ex) {
            ex.printStackTrace();
            throw new RestClientException("rest call failed");
        }
        return response;

    }

    public static RestTemplate getRestTemplate() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

        TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;

        SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy)
                .build();

        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);

        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();

        requestFactory.setHttpClient(httpClient);
        return new RestTemplate(requestFactory);
    }
}
