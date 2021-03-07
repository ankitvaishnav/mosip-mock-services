package io.mosip.proxy.abis;

import static java.util.Arrays.copyOfRange;

import java.io.IOException;
import java.io.InputStream;
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

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
@PropertySource("classpath:partner.properties")
public class CryptoCoreUtil {

	@Autowired
	private Environment env;

	private final static String RSA_ECB_OAEP_PADDING = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";

	private static final String KEY_SPLITTER = "#KEY_SPLITTER#";

	private static String certiPassword;

	private static String alias;

	private static String keystore;

	private static String filePath;

	private final static int THUMBPRINT_LENGTH = 32;

	public static void setPropertyValues() {
		Properties prop = new Properties();
		try {
			prop.load(CryptoCoreUtil.class.getClassLoader().getResourceAsStream("partner.properties"));
			certiPassword = prop.getProperty("cerificate.password");
			alias = prop.getProperty("cerificate.alias");
			keystore = prop.getProperty("certificate.keystore");
			filePath = prop.getProperty("certificate.filename");

		} catch (IOException e) {

			e.printStackTrace();
		}

	}

	public String decryptCbeff(String responseData) throws Exception {
		PrivateKeyEntry privateKey = getPrivateKeyEntryFromP12();
		byte[] responseBytes = org.apache.commons.codec.binary.Base64.decodeBase64(responseData);
		byte[] deryptedCbeffData = decryptCbeffData(responseBytes, privateKey);
		return new String(deryptedCbeffData);
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
		InputStream is = getClass().getResourceAsStream("/" + env.getProperty("certificate.filename"));
		keyStore.load(is, certiPassword.toCharArray());
		ProtectionParameter password = new PasswordProtection(certiPassword.toCharArray());
		PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(alias, password);

		return privateKeyEntry;
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
			byte[] randomIV = Arrays.copyOfRange(data, 0, 32);
//			byte[] randomIV = Arrays.copyOfRange(data, data.length - cipher.getBlockSize(), data.length);
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, randomIV);
			cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
			return cipher.doFinal(Arrays.copyOfRange(data, 32, data.length));
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public byte[] getCertificateThumbprint(Certificate cert) throws CertificateEncodingException {
		try {
			return DigestUtils.sha256(cert.getEncoded());
		} catch (CertificateEncodingException e) {
			throw e;
		}
	}
}
