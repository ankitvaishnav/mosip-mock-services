package io.mosip.proxy.abis;

import static java.util.Arrays.copyOfRange;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;

import io.mosip.proxy.abis.service.impl.ProxyAbisInsertServiceImpl;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
public class CryptoCoreUtil {

	private static final Logger logger = LoggerFactory.getLogger(CryptoCoreUtil.class);

	@Autowired
	private Environment env;

	private final static String RSA_ECB_OAEP_PADDING = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";

	private static final String KEY_SPLITTER = "#KEY_SPLITTER#";

	private static String certiPassword;

	private static String alias;

	private static String keystore;

	private static String filePath;

	private final static int THUMBPRINT_LENGTH = 32;

	private static String UPLOAD_FOLDER = System.getProperty("user.dir");

	/**
	 * This flag is added for development & debugging locally registration-processor-abis-sample.json
	 * If true then registration-processor-abis-sample.json will be picked from resources
	 */
	@Value("${local.development:false}")
	private boolean localDevelopment;


	public static void setPropertyValues() {
		Properties prop = new Properties();
		try {
			prop.load(Helpers.readStreamFromResources("partner.properties"));
			certiPassword = prop.getProperty("certificate.password");
			alias = prop.getProperty("certificate.alias");
			keystore = prop.getProperty("certificate.keystore");
			filePath = prop.getProperty("certificate.filename");

		} catch (IOException e) {

			e.printStackTrace();
		}
	}

	public String decryptCbeff(String responseData) throws Exception {
		PrivateKeyEntry privateKey = getPrivateKeyEntryFromP12();
		byte[] deryptedCbeffData;
		byte[] responseBytes = org.apache.commons.codec.binary.Base64.decodeBase64(responseData);
		String version = new String(copyOfRange(responseBytes, 0, 6), StandardCharsets.UTF_8);
		logger.info("Version of encryption: "+version);
		if(version.equalsIgnoreCase("VER_R2")){
			deryptedCbeffData = decryptCbeffDataVerR2(responseBytes, privateKey);
		} else {
			deryptedCbeffData = decryptCbeffData(responseBytes, privateKey);
		}
		return new String(deryptedCbeffData, StandardCharsets.UTF_8);
	}

	public static void setCertificateValues(String filePathVal, String keystoreVal, String passwordVal,
											String aliasVal) {
		alias = aliasVal;
		filePath = filePathVal;
		keystore = keystoreVal;
		certiPassword = passwordVal;

	}

	private PrivateKeyEntry getPrivateKeyEntryFromP12() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, UnrecoverableEntryException {
		if (null == certiPassword || certiPassword.isEmpty()) {
			setPropertyValues();
		}
		KeyStore keyStore = KeyStore.getInstance(keystore);
		InputStream is = new FileInputStream(UPLOAD_FOLDER+"/"+ filePath);
		keyStore.load(is, certiPassword.toCharArray());
		ProtectionParameter password = new PasswordProtection(certiPassword.toCharArray());
		PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(alias, password);

		return privateKeyEntry;
	}

	private byte[] decryptCbeffDataVerR2(byte[] responseData, PrivateKeyEntry privateKey) throws Exception {
		int cipherKeyandDataLength = responseData.length;
		int keySplitterLength = KEY_SPLITTER.length();
		int keyDemiliterIndex = getSplitterIndex(responseData, 0, KEY_SPLITTER);
		try {
			/*
				VER_BYTES (6 bytes) - Certificate Thumbprint (32 bytes) - Encrypted Random AES Key (256 bytes) - KEY_SPLITTER bytes -
				Random AAD (32 bytes) - IV/Nonce First 12 bytes from AAD (12 bytes) - Encrypted data using AES (Remaining bytes)
			*/
			byte[] version = copyOfRange(responseData, 0, 6);
			byte[] thumbprint = copyOfRange(responseData, 6, 38);
			byte[] encryptedSymmetricKey = copyOfRange(responseData, 38, 294);
			byte[] part_2 = copyOfRange(responseData, 294+keySplitterLength, responseData.length);
			byte[] aad = copyOfRange(part_2, 0, 32);
			byte[] ivOrNounce = copyOfRange(part_2, 32, 44);
			byte[] encryptedData = copyOfRange(part_2, 44, part_2.length);

			byte[] certThumbprint = getCertificateThumbprint(privateKey.getCertificate());

			if(localDevelopment){
				logger.info("version: "+new String(copyOfRange(version, 0, 6), StandardCharsets.UTF_8));
				logger.info("thumbprint: "+bytesToHex(thumbprint));
				logger.info("encryptedSymmetricKey: "+ Base64.getEncoder().encodeToString(encryptedSymmetricKey));
				logger.info("aad: "+ Base64.getEncoder().encodeToString(aad));
				logger.info("ivOrNounce: "+ Base64.getEncoder().encodeToString(ivOrNounce));
			}
			if(!Arrays.equals(thumbprint, certThumbprint)){
				logger.info("Certificate thumbprints are not matching ["+bytesToHex(thumbprint)+"], ["+bytesToHex(certThumbprint)+"]");
				throw new Exception("Certificate thumbprints are not matching.");
			}
			/*
				Compare certificates thumbprint to verify certificate matches or not.
				If does not match data will not get decrypted
			*/
			/*if (!Arrays.equals(dataThumbprint, certThumbprint)) {
				throw new CbeffException("Error in generating Certificate Thumbprint.");
			}*/

			byte[] decryptedSymmetricKey = decryptRandomSymKey(privateKey.getPrivateKey(), encryptedSymmetricKey);
			if(localDevelopment){
				logger.info("decryptedSymmetricKey: "+ bytesToHex(decryptedSymmetricKey));
			}
			SecretKey symmetricKey = new SecretKeySpec(decryptedSymmetricKey, 0, decryptedSymmetricKey.length, "AES");
			return decryptCbeffData(symmetricKey, encryptedData, ivOrNounce, aad);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	@SuppressWarnings("unused")
	private byte[] decryptCbeffData(byte[] responseData, PrivateKeyEntry privateKey) throws Exception {
		int cipherKeyandDataLength = responseData.length;
		int keySplitterLength = KEY_SPLITTER.length();
		int keyDemiliterIndex = getSplitterIndex(responseData, 0, KEY_SPLITTER);
		try {
			/*
				Copy the bytes from 0 location till KEY_SPLITTER index into an byte array. 
				Since 1.1.4 copied bytes will be Certificate Thumbprint + encrypted random symmetric key.
				Certificate thumbprint will be used as key/certificate identifier.
				Since 1.1.4 certificate thumbprint will be prepended to encrypted random symmetric key.
				Split the copied bytes from index 0 to 32 to get the certificate thumbprint.
				Split the copied bytes from index 32 to length of copied bytes to get the random symmetric key.
				Before 1.1.4 copied bytes does not prepended with certificate thumbprint, required to be used as encrypted random key.
			*/
			byte[] copiedBytes = copyOfRange(responseData, 0, keyDemiliterIndex);
			/*
				To Handle both 1.1.4 and before, check the size of copiedBytes.
				If copied bytes are more than 256, certificate is prepended to the encrypted random key 
				Otherwise copied bytes contains only encypted random key.
			*/
			byte[] dataCertThumbprint = null;
			byte[] encryptedSymmetricKey = null;
			if (copiedBytes.length > 256){
				dataCertThumbprint = Arrays.copyOfRange(copiedBytes, 0, THUMBPRINT_LENGTH);
				encryptedSymmetricKey = Arrays.copyOfRange(copiedBytes, THUMBPRINT_LENGTH, copiedBytes.length);
			} else {
				encryptedSymmetricKey = copiedBytes;
			}
			
			byte[] encryptedCbeffData = copyOfRange(responseData, keyDemiliterIndex + keySplitterLength, cipherKeyandDataLength);
			
			byte[] certThumbprint = getCertificateThumbprint(privateKey.getCertificate());
			/*
				Compare certificates thumbprint to verify certificate matches or not. 
				If does not match data will not get decrypted
			*/
			/*if (!Arrays.equals(dataThumbprint, certThumbprint)) {
				throw new CbeffException("Error in generating Certificate Thumbprint.");
			}*/

			byte[] decryptedSymmetricKey = decryptRandomSymKey(privateKey.getPrivateKey(), encryptedSymmetricKey);
			SecretKey symmetricKey = new SecretKeySpec(decryptedSymmetricKey, 0, decryptedSymmetricKey.length, "AES");
			return decryptCbeffData(symmetricKey, encryptedCbeffData);
		} catch (Exception e) {
			e.printStackTrace();
		}
		throw new Exception("Error In Data Decryption.");
	}	

	private static int getSplitterIndex(byte[] encryptedData, int keyDemiliterIndex, String keySplitter) {
		final byte keySplitterFirstByte = keySplitter.getBytes()[0];
		final int keySplitterLength = keySplitter.length();
		for (byte data : encryptedData) {
			if (data == keySplitterFirstByte) {
				final String keySplit = new String(
						copyOfRange(encryptedData, keyDemiliterIndex, keyDemiliterIndex + keySplitterLength));
				if (keySplitter.equals(keySplit)) {
					break;
				}
			}
			keyDemiliterIndex++;
		}
		return keyDemiliterIndex;
	}

	/**
	 *
	 * @param privateKey
	 * @param randomSymKey
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 */
	private byte[] decryptRandomSymKey(PrivateKey privateKey, byte[] randomSymKey)
			throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, InvalidKeyException {

		try {
			Cipher cipher = Cipher.getInstance(RSA_ECB_OAEP_PADDING);
			OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
					PSpecified.DEFAULT);
			cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
			return cipher.doFinal(randomSymKey);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmException(e);
		} catch (NoSuchPaddingException e) {
			throw new NoSuchPaddingException(e.getMessage());
		} catch (java.security.InvalidKeyException e) {
			throw new InvalidKeyException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new InvalidAlgorithmParameterException(e);
		}
	}

	private byte[] decryptCbeffData(SecretKey key, byte[] data) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
			byte[] randomIV = Arrays.copyOfRange(data, data.length - cipher.getBlockSize(), data.length);
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, randomIV);
			cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
			return cipher.doFinal(Arrays.copyOf(data, data.length - cipher.getBlockSize()));
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	private byte[] decryptCbeffData(SecretKey key, byte[] data, byte[] iv, byte[] aad) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
			cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
			cipher.updateAAD(aad);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public byte[] getCertificateThumbprint(Certificate cert) throws CertificateEncodingException {
		if(localDevelopment){
			logger.info(cert.getPublicKey().toString());
			logger.info(Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded()));
		}
		return DigestUtils.sha256(cert.getPublicKey().getEncoded());
	}
	private static String bytesToHex(byte[] hash) {
		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < hash.length; i++) {
			String hex = Integer.toHexString(0xff & hash[i]);
			if (hex.length() == 1) {
				hexString.append('0');
			}
			hexString.append(hex);
		}
		return hexString.toString();
	}

}
