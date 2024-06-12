package com.quart233.snippets

import android.util.Base64
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher


class RSA (base64: String) {
    private val decoded = Base64.decode(base64, Base64.DEFAULT)
    private val keyFactory = KeyFactory.getInstance("RSA")
    private val spec = X509EncodedKeySpec(decoded)
    private val key = keyFactory.generatePublic(spec)

    fun decrypt(ciphertext: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.DECRYPT_MODE, key)
            return cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            // Handle exceptions like NoSuchAlgorithmException, InvalidKeyException, BadPaddingException
            throw RuntimeException("Error during RSA decryption", e)
        }
    }
    fun encrypt(ciphertext: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            // Handle exceptions like NoSuchAlgorithmException, InvalidKeyException, BadPaddingException
            throw RuntimeException("Error during RSA encryption", e)
        }
    }
}