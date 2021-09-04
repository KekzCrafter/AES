package de.kekz;

import java.io.File;
import java.io.FileWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	/**
	 * Utils
	 */
	public static SecretKey generateSecretKey(int keysize) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keysize, SecureRandom.getInstanceStrong());

		return keyGen.generateKey();
	}

	public static byte[] generateRandomBytes(int size) {
		byte[] nonce = new byte[size];
		new SecureRandom().nextBytes(nonce);

		return nonce;
	}

	public static String convertBytesToHex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
			result.append(String.format("%02x", b));
		}

		return result.toString();
	}

	public static byte[] convertHexToBytes(String hex) {
		int len = hex.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
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

	public static File encrypt(File input, SecretKey secret, byte[] vector) {
		File output = new File(input.getParent() + "\\encrypted-" + input.getName() + "");

		try {
			output.createNewFile();

			FileWriter writer = new FileWriter(output);
			Scanner scanner = new Scanner(input);

			while (scanner.hasNext()) {
				String line = scanner.nextLine();
				String lineEncrypted = encrypt(line, secret, vector) + "\n";

				writer.write(lineEncrypted);
			}

			writer.close();
			scanner.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return output;
	}

	public static File decrypt(File input, SecretKey secret, byte[] vector) {
		if (!input.getName().startsWith("encrypted-")) {
			return null;
		}

		String filename = "decrypted-" + input.getName().split("encrypted-")[1];
		File output = new File(input.getParent() + "\\" + filename);

		try {
			output.createNewFile();

			FileWriter writer = new FileWriter(output);
			Scanner scanner = new Scanner(input);

			while (scanner.hasNext()) {
				String line = scanner.nextLine();
				String lineEncrypted = decrypt(line, secret, vector) + "\n";

				writer.write(lineEncrypted);
			}

			writer.close();
			scanner.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return output;
	}

	public static void main(String[] args) throws Exception {
		File file = new File("");
		File encryptedFile = new File("");

		String text = "https://paradoxanticheat.de/en/maintenance/";

		String keyBase64 = "MTQ1MDM4ZDc5MDIwMWNhMjJhMzE2ZjcwNTIwYzAyYzE4NTQyZmEzODQxYWI0MWVkMTZkM2Q4OTFhNzhjZjk3NA==";
		String keyHex = new String(Base64.getDecoder().decode(keyBase64.getBytes()));
		byte[] keyBytes = convertHexToBytes(keyHex);

		SecretKey secretKey = new SecretKeySpec(keyBytes, 0, 32, "AES");

		String vectorBase64 = "ODFmZGRlZDVlYTM0ZDU1ZGM1NTQ1MzMyYzFhZmQ4YmM=";
		String vectorHex = new String(Base64.getDecoder().decode(vectorBase64.getBytes()));
		byte[] vectorBytes = convertHexToBytes(vectorHex);

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

		byte[] randomKeyBytes = generateSecretKey(key_length).getEncoded();
		byte[] randomVectorBytes = generateRandomBytes(vector_length);

		String randomKeyHex = convertBytesToHex(randomKeyBytes);
		String randomVectorHex = convertBytesToHex(randomVectorBytes);

		String randomKeyBase64 = Base64.getEncoder().encodeToString(randomKeyHex.getBytes());
		String randomVectorBase64 = Base64.getEncoder().encodeToString(randomVectorHex.getBytes());

		System.out.println("\n\nRandom Secret Key (Hex): " + randomKeyHex);
		System.out.println("Random Secret Key (Base64 Encoding): " + randomKeyBase64);
		System.out.println("\nRandom Vector (Hex): " + randomVectorHex);
		System.out.println("Random Vector (Base64 Encoding): " + randomVectorBase64);

		encrypt(file, secretKey, vectorBytes);
		decrypt(encryptedFile, secretKey, vectorBytes);
	}
}
