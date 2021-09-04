package de.kekz;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	/**
	 * Utils
	 */
	public static SecretKey generateAESSecretKey(int keysize) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keysize, SecureRandom.getInstanceStrong());

		return keyGen.generateKey();
	}

	public static byte[] getRandomNonce(int numBytes) {
		byte[] nonce = new byte[numBytes];
		new SecureRandom().nextBytes(nonce);

		return nonce;
	}

	public static String getBytesToHex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
			result.append(String.format("%02x", b));
		}

		return result.toString();
	}

	public static byte[] getHexToBytes(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/**
	 * AES Encryption/Decryption methods
	 */
	private static String cipher_algo = "AES/CBC/PKCS5PADDING";
	private static int vector_length = 16;
	private static int key_length = 256;

	public static String encrypt(String data, SecretKey secret, byte[] vector) throws Exception {
		Cipher cipher = Cipher.getInstance(cipher_algo);
		cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(vector));

		String encryptedText = Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
		return encryptedText;
	}

	public static String decrypt(String data, SecretKey secret, byte[] vector) throws Exception {
		Cipher cipher = Cipher.getInstance(cipher_algo);
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(vector));

		byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(data.getBytes()));
		return new String(plainText);

	}

	public static void main(String[] args) throws Exception {
		String text = "https://paradoxanticheat.de/en/maintenance/";

		String keyBase64 = "ZDYzZjIzMjdhOTdlNTQwNTg1OTM3ZDFjYmU0NjFlY2JjY2FiZWJkYzBhMTE1YTk1NTkyODhkNjliMzJkZDI1Nw==";
		String keyHex = new String(Base64.getDecoder().decode(keyBase64.getBytes()));
		byte[] keyBytes = getHexToBytes(keyHex);

		SecretKey secretKey = new SecretKeySpec(keyBytes, 0, 32, "AES");

		String vectorBase64 = "Yzc2NmZiZjY1ODdiZDRjMWY0NWFkNjI0OGEzZDIxMGQ=";
		String vectorHex = new String(Base64.getDecoder().decode(vectorBase64.getBytes()));
		byte[] vectorBytes = getHexToBytes(vectorHex);

		String encryptedText = encrypt(text, secretKey, vectorBytes);
		String decryptedText = decrypt(encryptedText, secretKey, vectorBytes);

		int length = encryptedText.length();

		System.out.println("------ Key & Vector ------");
		System.out.println("Secret Key (Base64): " + keyBase64);
		System.out.println("Vector (Base64): " + vectorBase64);

		System.out.println("\n------ AES Encryption ------");
		System.out.println("Input (Raw): " + text);
		System.out.println("Output (Decrypted / Base64): " + encryptedText + " (" + length + ")");

		System.out.println("\n------ AES Decryption ------");
		System.out.println("Input (Encrypted / Base64): " + encryptedText);
		System.out.println("Output (Raw): " + decryptedText);

		if (text.equals(decryptedText)) {
			System.out.println("\nOK: The decrypted data equals the input data.");
		} else {
			System.out.println("\nERROR: The decrypted data doesn't equal the input data.");
		}

		byte[] randomKeyBytes = generateAESSecretKey(key_length).getEncoded();
		byte[] randomVectorBytes = getRandomNonce(vector_length);

		String randomKeyHex = getBytesToHex(randomKeyBytes);
		String randomVectorHex = getBytesToHex(randomVectorBytes);

		String randomKeyBase64 = Base64.getEncoder().encodeToString(randomKeyHex.getBytes());
		String randomVectorBase64 = Base64.getEncoder().encodeToString(randomVectorHex.getBytes());

		System.out.println("\n\nRandom Secret Key (Hex): " + randomKeyHex);
		System.out.println("Random Secret Key (Base64 Encoding): " + randomKeyBase64);
		System.out.println("\nRandom Vector Key (Hex): " + randomVectorHex);
		System.out.println("Random Vector Key (Base64 Encoding): " + randomVectorBase64);
	}
}
