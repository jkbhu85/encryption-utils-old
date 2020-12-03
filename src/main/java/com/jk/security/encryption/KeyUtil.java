package com.jk.security.encryption;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import com.jk.security.AppUtils;
import com.jk.security.Consts;

public class KeyUtil {

	public static byte[] getRandom(final int numBytes) {
		byte[] random = new byte[numBytes];
		new SecureRandom().nextBytes(random);
		return random;
	}

	public static SymmetricKey createNewKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(Consts.SYMMETRIC_ENCRYPTION_ALGORITHM);
			keyGenerator.init(256, SecureRandom.getInstanceStrong());
			return new SymmetricKey(keyGenerator.generateKey(),
					getRandom(Consts.SYMMETRIC_ENCRYPTION_NUMBER_OF_VI_BYTES));
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static void storeKeyData(String dir, SymmetricKeyEncodedEncryptedData symmetricKeyData) {
		String fileName = AppUtils.fileName(Consts.SYMMETRIC_KEY_FILE_NAME, AppUtils.getDateTime());
		storeKeyData(dir, fileName, symmetricKeyData);
	}

	public static void storeKeyData(String dir, String fileName, SymmetricKeyEncodedEncryptedData symmetricKeyData) {
		try {
			Properties properties = new Properties();
			properties.setProperty(Consts.PROPERTY_SECRET_KEY, symmetricKeyData.getEncodedEncryptedKey());
			properties.setProperty(Consts.PROPERTY_IV, symmetricKeyData.getEncodedEncryptedIv());

			FileWriter fileWriter = new FileWriter(dir + File.separator + fileName);
			properties.store(fileWriter, "Encrypted encoded keys for symmetric encryption");
			fileWriter.flush();
			fileWriter.close();
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static SymmetricKeyEncodedEncryptedData loadKeyData(String dir, String fileName) {
		try {
			InputStream in = new FileInputStream(dir + File.separator + fileName);
			Properties properties = new Properties();
			properties.load(in);
			return new SymmetricKeyEncodedEncryptedData(
					properties.getProperty(Consts.PROPERTY_SECRET_KEY),
					properties.getProperty(Consts.PROPERTY_IV));
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static SymmetricKey createKey(byte[] key, byte[] iv) {
		try {
			SecretKeySpec keySpec = new SecretKeySpec(key, Consts.SYMMETRIC_ENCRYPTION_ALGORITHM);
			return new SymmetricKey(keySpec, iv);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
