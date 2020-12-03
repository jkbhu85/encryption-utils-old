package com.jk.security.encryption;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.jk.security.AppUtils;
import com.jk.security.Consts;

public class KeyPairUtil {

	public static KeyPair createNewKeyPair(final int keySize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Consts.ASYMMETRIC_ENCRYPTION_ALGORITHM,
					Consts.SECURITY_PROVIDER);
			keyPairGenerator.initialize(keySize);
			return keyPairGenerator.generateKeyPair();
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static KeyPair loadKeyPairFromStore(String dir, String publicKeyFileName, String privateKeyFileName) {
		String.valueOf(new char[] {});
		try {
			String encodedPublicKey = new String(Files.readAllBytes(Paths.get(dir, publicKeyFileName)));
			String encodedPrivateKey = new String(Files.readAllBytes(Paths.get(dir, privateKeyFileName)));
			return createKeyPair(encodedPublicKey, encodedPrivateKey);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static void storeKeyPair(String dir, KeyPair keyPair) {
		String publicKeyFileName = AppUtils.fileName(Consts.PUBLIC_KEY_FILE_NAME, AppUtils.getDateTime());
		String privateKeyFileName = AppUtils.fileName(Consts.PRIVATE_KEY_FILE_NAME, AppUtils.getDateTime());
		storeKeyPair(dir, publicKeyFileName, privateKeyFileName, keyPair);
	}

	public static void storeKeyPair(String dir, String publicKeyFileName, String privateKeyFileName, KeyPair keyPair) {
		try {
			Files.write(
					Paths.get(dir, publicKeyFileName),
					Base64.encodeBase64(keyPair.getPublic().getEncoded()),
					StandardOpenOption.CREATE_NEW);
			Files.write(
					Paths.get(dir, privateKeyFileName),
					Base64.encodeBase64(keyPair.getPrivate().getEncoded()),
					StandardOpenOption.CREATE_NEW);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static KeyPair createKeyPair(String encodedPublicKey, String encodedPrivateKey) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(Consts.ASYMMETRIC_ENCRYPTION_ALGORITHM);

			// load public key
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(encodedPublicKey));
			PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

			// load private key
			PKCS8EncodedKeySpec pcksKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(encodedPrivateKey));
			PrivateKey privateKey = keyFactory.generatePrivate(pcksKeySpec);

			return new KeyPair(publicKey, privateKey);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
