package com.lebarautils;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class EncodeDecode {
    EncodeDecode() {
    }

    public static String decryptData(String var0, String var1) {
        PasswordAES128Algorithm var2 = new PasswordAES128Algorithm();

        try {
            byte[] var3 = Base64.getDecoder().decode(var1);
            System.out.println("decoded: " + Arrays.toString(var3));
            String var4 = String.format("%040x", new BigInteger(1, var3));
            byte[] var5 = PasswordAES128Algorithm.hex2Bytes(var0);
            System.out.println("Key: " + Arrays.toString(var5));
            System.out.println("hexValue: " + var4);
            String var6 = var2.decryptWithCBC(var4, var5);
            System.out.println(var6);
            return var6;
        } catch (Exception var7) {
            Logger.getLogger(EncodeDecode.class.getName()).log(Level.SEVERE, (String)null, var7);
            return "error";
        }
    }

    public static void main(String[] var0) {
        new PasswordAES128Algorithm();

        try {
            String var2 = "z2LboXa5YGqquwxYBlIj26nohX4wfu+HbjEl5NwmddU=";
            decryptData("31323334353637383930313131313130", var2);
        } catch (Exception var3) {
            Logger.getLogger(EncodeDecode.class.getName()).log(Level.SEVERE, (String)null, var3);
        }

    }

    public static String encryptData(String var0, String var1) throws Exception {
        byte[] var2 = var1.getBytes("UTF-8");
        SecretKeySpec var3 = new SecretKeySpec(var2, "AES");
        byte[] var4 = genRandomBytes(16);
        IvParameterSpec var5 = new IvParameterSpec(var4);
        Cipher var6 = Cipher.getInstance("AES/CBC/PKCS5Padding");
        var6.init(1, var3, var5);
        byte[] var7 = var6.doFinal(var0.getBytes("UTF-8"));
        byte[] var8 = new byte[var7.length + 16];
        System.arraycopy(var4, 0, var8, 0, 16);
        System.arraycopy(var7, 0, var8, 16, var7.length);
        return Base64.getEncoder().encodeToString(var8);
    }

    public static byte[] genRandomBytes(int var0) {
        byte[] var1 = new byte[var0];
        SecureRandom var2 = new SecureRandom();
        var2.nextBytes(var1);
        return var1;
    }
}
