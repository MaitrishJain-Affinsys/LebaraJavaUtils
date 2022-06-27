package com.lebarautils;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordAES128Algorithm {
    private static byte[] raw;
    private static byte[] raw_AES256_KEY_DEFAULT = new byte[]{27, 8, 70, 38, -111, 120, 90, -60, -40, 13, 73, 115, 0, -20, 33, 109, -83, -51, -91, 99, 50, 94, -73, 102, -112, 26, -118, 52, -32, 113, 123, 103};
    private static byte[] raw_AES128_KEY_CTZ2 = new byte[]{-70, -30, 9, -41, 39, 32, -94, -113, 51, 40, -63, 23, -101, 68, -54, -3};
    private static byte[] raw_AES128_KEY_VM = new byte[]{-103, -76, 6, 105, -23, 59, -49, 80, -123, 102, 34, 109, -5, 104, 32, 110};
    private static byte[] raw_AES128_KEY_DEFAULT = new byte[]{12, -60, -63, -17, -86, 64, -75, -54, -44, 53, 54, 123, 111, 70, -119, -22};
    private String encoding = "UTF-8";

    public PasswordAES128Algorithm() {
    }

    private byte[] checkAlgorithm(String var1) {
        if ("AES256 + KEY_DEFAULT".equals(var1)) {
            raw = raw_AES256_KEY_DEFAULT;
        } else if ("AES128 + KEY_CTZ2".equals(var1)) {
            raw = raw_AES128_KEY_CTZ2;
        } else if ("AES128 + KEY_VM".equals(var1)) {
            raw = raw_AES128_KEY_VM;
        } else if ("AES128 + KEY_DEFAULT".equals(var1)) {
            raw = raw_AES128_KEY_DEFAULT;
        }

        return raw;
    }

    public String encrypt(String var1, String var2) throws Exception {
        return var1 != null && var1.length() != 0 ? this.encrypt(var1, this.checkAlgorithm(var2)) : var1;
    }

    public String decrypt(String var1, String var2) throws Exception {
        return var1 != null && var1.length() != 0 ? this.decrypt(var1, this.checkAlgorithm(var2)) : var1;
    }

    public String encryptWithCBC(String var1, String var2) throws Exception {
        return var1 != null && var1.length() != 0 ? this.encryptWithCBC(var1, this.checkAlgorithm(var2)) : var1;
    }

    public String decryptWithCBC(String var1, String var2) throws Exception {
        return var1 != null && var1.length() != 0 ? this.decryptWithCBC(var1, this.checkAlgorithm(var2)) : var1;
    }

    public void setEncoding(String var1) {
        this.encoding = var1;
    }

    public String encrypt(String var1, byte[] var2) throws Exception {
        String var3 = null;

        try {
            SecretKeySpec var4 = new SecretKeySpec(var2, "AES");
            Cipher var5 = Cipher.getInstance("AES");
            var5.init(1, var4);
            byte[] var6 = var5.doFinal(var1.getBytes(this.encoding));
            var3 = bytes2Hex(var6);
            return var3;
        } catch (Exception var7) {
            throw var7;
        }
    }

    public String decrypt(String var1, byte[] var2) throws Exception {
        String var3 = null;
        byte[] var4 = hex2Bytes(var1);

        try {
            Cipher var5 = Cipher.getInstance("AES");
            SecretKeySpec var6 = new SecretKeySpec(var2, "AES");
            var5.init(2, var6);
            byte[] var7 = var5.doFinal(var4);
            var3 = new String(var7);
            var5 = Cipher.getInstance("AES");
            return var3;
        } catch (Exception var8) {
            throw var8;
        }
    }

    public String encryptWithCBC(String var1, byte[] var2) throws Exception {
        String var3 = null;

        try {
            SecretKeySpec var4 = new SecretKeySpec(var2, "AES");
            Cipher var5 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecureRandom var6 = new SecureRandom();
            byte[] var7 = new byte[16];
            var6.nextBytes(var7);
            IvParameterSpec var8 = new IvParameterSpec(var7, 0, 16);
            var5.init(1, var4, var8);
            byte[] var9 = var5.doFinal(var1.getBytes(this.encoding));
            byte[] var10 = new byte[var9.length + 16];
            System.arraycopy(var7, 0, var10, 0, 16);
            System.arraycopy(var9, 0, var10, 16, var9.length);
            var3 = bytes2Hex(var10);
            return var3;
        } catch (Exception var11) {
            var11.printStackTrace();
            throw var11;
        }
    }

    public String decryptWithCBC(String var1, byte[] var2) throws Exception {
        String var3 = null;

        try {
            byte[] var4 = hex2Bytes(var1);
            byte[] var5 = new byte[16];
            byte[] var6 = new byte[var4.length - 16];
            System.arraycopy(var4, 0, var5, 0, 16);
            System.arraycopy(var4, 16, var6, 0, var4.length - 16);
            Cipher var7 = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec var8 = new SecretKeySpec(var2, "AES");
            IvParameterSpec var9 = new IvParameterSpec(var5, 0, 16);
            var7.init(2, var8, var9);
            byte[] var10 = var7.doFinal(var6);
            var3 = new String(var10);
            return var3;
        } catch (Exception var11) {
            throw var11;
        }
    }

    public static String bytes2Hex(byte[] var0) {
        StringBuffer var1 = new StringBuffer();
        String var2 = null;
        byte[] var3 = var0;
        int var4 = var0.length;

        for(int var5 = 0; var5 < var4; ++var5) {
            byte var6 = var3[var5];
            var2 = Integer.toHexString(var6 & 255);
            if (var2.length() == 1) {
                var1.append('0');
            }

            var1.append(var2);
        }

        return var1.toString();
    }

    public static byte[] hex2Bytes(String var0) {
        byte[] var1 = new byte[var0.length() / 2];

        for(int var2 = 0; var2 < var0.length(); var2 += 2) {
            var1[var2 / 2] = Integer.decode("0x" + var0.charAt(var2) + var0.charAt(var2 + 1)).byteValue();
        }

        return var1;
    }
}
