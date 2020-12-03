package com.jk.security;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.Security;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.jk.security.encryption.AsymmetricEncryptionService;
import com.jk.security.encryption.EncryptionService;
import com.jk.security.encryption.EncryptionUtils;
import com.jk.security.encryption.KeyPairUtil;
import com.jk.security.encryption.KeyUtil;
import com.jk.security.encryption.SymmetricEncryptionParameters;
import com.jk.security.encryption.SymmetricEncryptionService;
import com.jk.security.encryption.SymmetricKey;
import com.jk.security.encryption.SymmetricKeyEncodedEncryptedData;

public class EncryptionUtilApplication {

	private static final String DIR_BASE_PATH = "/home/jitendra/dev/security/keys";
	private static final String RSA_DIR_PATH = DIR_BASE_PATH + File.separator + "rsa";
	
	private static final String FILE_NAME_PUBLIC_KEY = "01_ramapi_public.key.txt";
	private static final String FILE_NAME_PRIVATE_KEY = "01_ramapi_private.key.txt";
	private static final String FILE_NAME_SYMMETRIC_KEY = "symmetric2020-07-24-00-30-58.key.properties";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) {
		encryptText();
		System.out.println("Operation completed.");
	}
	
	static void printTaskName(String msg) {
		System.out.println(":: " + msg + " ::");
	}
	
	static void encryptText() {
		printTaskName("Text encryption");
		final String text = "269b7f99-58b5-426a-aa02-c0e4d2168328";
		final EncryptionService encryptionService = getAsymmetricEncryptionService();
		final byte[] encryptedData = encryptionService.encrypt(text.getBytes());
		final String encodedEncryptedData = Base64.encodeBase64String(encryptedData);
		AppUtils.printAsBlock("Text to encrypt", text);
		AppUtils.printAsBlock("Encrypted encoded output", encodedEncryptedData);
	}
	
	static void generateAndStoreRsaKeys() {
		printTaskName("Generate and store RSA keys");
		final int keySize = 2048;
		KeyPair keyPair = KeyPairUtil.createNewKeyPair(keySize);
		KeyPairUtil.storeKeyPair(RSA_DIR_PATH, keyPair);
	}
	
	static void encryptAndStoreFiles() {
		printTaskName("Encrypt and store files");
		final String basePath = "/home/jitendra/dev/keys/certs";
		final List<String> fileNames = AppUtils.asUnmodifiableList("keystore", "truststore");
		EncryptionService encryptionService = getAsymmetricEncryptionService();
		
		try {
			for (String fileName : fileNames) {
				byte[] fileContent = Files.readAllBytes(Paths.get(basePath, fileName));
				byte[] encryptedFileContent = encryptionService.encrypt(fileContent);
				String newFileName = fileName + ".rsa.encrypted";
				Files.write(Paths.get(basePath, "encrypted", newFileName), encryptedFileContent, StandardOpenOption.CREATE_NEW);
				System.out.println("Original file: [" + fileName + "]" + "  Encrypted file: [" + newFileName + "]");
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	static void generateAndStoreEncryptedAesKeys() {
		printTaskName(":: Generating and storing encrypted keys for AES ::");
		EncryptionService encryptionService = getAsymmetricEncryptionService();
		// generate new key
		SymmetricKey symmetricKey = KeyUtil.createNewKey();

		// encrypt components of the key
		byte[] encryptedKey = encryptionService.encrypt(symmetricKey.getSecretKey().getEncoded());
		byte[] encryptedIv = encryptionService.encrypt(symmetricKey.getIv());
		SymmetricKeyEncodedEncryptedData encodedEncryptedData = SymmetricKeyEncodedEncryptedData.builder()
				.encodedEncryptedKey(Base64.encodeBase64String(encryptedKey))
				.encodedEncryptedIv(Base64.encodeBase64String(encryptedIv))
				.build();
		
		KeyUtil.storeKeyData(DIR_BASE_PATH + File.separator + "aes", encodedEncryptedData);
	}
	
	static EncryptionService getAsymmetricEncryptionService() {
		KeyPair keyPair = KeyPairUtil.loadKeyPairFromStore(RSA_DIR_PATH, FILE_NAME_PUBLIC_KEY, FILE_NAME_PRIVATE_KEY);
		return new AsymmetricEncryptionService(EncryptionUtils.getDefaultParams(keyPair));
	}
	
	static EncryptionService getSymmetricEncryptionService() {
		final String basePath = "/home/jitendra/dev/keys/aes";
		SymmetricKeyEncodedEncryptedData data = KeyUtil.loadKeyData(basePath, FILE_NAME_SYMMETRIC_KEY);
		EncryptionService encryptionService = getAsymmetricEncryptionService();
		
		byte[] encryptedSecretKeyData = Base64.decodeBase64(data.getEncodedEncryptedKey());
		System.out.println("Number of bytes in encryptedSecretKeyData: " + encryptedSecretKeyData.length);
		byte[] secretKeyValue = encryptionService.decrypt(encryptedSecretKeyData);
		byte[] iv = encryptionService.decrypt(Base64.decodeBase64(data.getEncodedEncryptedIv()));
		
		SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyValue, Consts.SYMMETRIC_ENCRYPTION_ALGORITHM);
		SymmetricKey symmetricKey = new SymmetricKey(secretKeySpec, iv);
		SymmetricEncryptionParameters symmetricEncryptionParameters = EncryptionUtils.getDefaultParameters(symmetricKey);
		return new SymmetricEncryptionService(symmetricEncryptionParameters);
	}

	
	static void testRsaEncryption() {
		System.out.println(":: Testing RSA encryption ::\n");
		EncryptionService service = getAsymmetricEncryptionService();
		final String text = getTestText(200);
		AppUtils.printAsBlock("Original message", text);
		
		byte[] encrypted = service.encrypt(text.getBytes());
		String decryptedMessage = new String(service.decrypt(encrypted));
		
		AppUtils.printAsBlock("Decrypted message", decryptedMessage);
	}
	
	static String getTestText(int textLength) {
		final String seed = "AAAA BBBB CCCC DDDD ";
		final int seedLength = seed.length();
		int len = 0;
		String s = "";
		while (len < textLength) {
			if (len + seedLength > textLength) {
				s += seed.substring(0, textLength - len);
			}
			else {
				s += seed;
			}
			len += seedLength;
		}
		return s;
	}
	
	static void testAesEncryption() {
		System.out.println(":: Testing AES encryption ::\n");
		EncryptionService service = getSymmetricEncryptionService();
		String text = "This is test message";
		AppUtils.printAsBlock("Original message", text);
		
		byte[] encrypted = service.encrypt(text.getBytes());
		String decryptedMessage = new String(service.decrypt(encrypted));
		
		AppUtils.printAsBlock("Decrypted message", decryptedMessage);
	}
}
