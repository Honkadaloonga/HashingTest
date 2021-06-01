package com.p5zf2c46j;

import static java.lang.Integer.rotateRight;

public class HashingTest {
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private static final int[] H = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    public static String SHA256(byte[] input) {
        int messageBitLength = input.length * 8;
        int blockCount = (int) Math.ceil(messageBitLength / 512d);
        if (messageBitLength % 512 >= 447 || (messageBitLength > 0 && messageBitLength % 512 == 0)) {
            blockCount++;
        }
        int[][] blocks = new int[blockCount][16];
        for (int i = 0; i < input.length; i++) {
            blocks[i/64][(i%64)/4] |= input[i] << (8*(3-(i%4)));
        }
        blocks[input.length/64][(input.length%64)/4] |= 1 << (8*(4-(input.length%4))-1);
        blocks[blocks.length-1][15] = input.length*8;

        int[] H0 = H.clone();

        for (int[] block : blocks) {
            int[] W = new int[64];
            System.arraycopy(block, 0, W, 0, block.length);
            for (int j = 16; j < W.length; j++) {
                W[j] = sigma1(W[j - 2]) + W[j - 7] + sigma0(W[j - 15]) + W[j - 16];
            }

            int[] H1 = H0.clone();
            for (int j = 0; j < W.length; j++) {
                int T1 = Sigma1(H1[4]) + Ch(H1[4], H1[5], H1[6]) + H1[7] + K[j] + W[j];
                int T2 = Sigma0(H1[0]) + Maj(H1[0], H1[1], H1[2]);

                //noinspection SuspiciousSystemArraycopy
                System.arraycopy(H1, 0, H1, 1, H1.length - 1);

                H1[0] = T1 + T2;
                H1[4] += T1;
            }

            for (int j = 0; j < H0.length; j++) {
                H0[j] += H1[j];
            }
        }

        StringBuilder result = new StringBuilder();
        for (int i : H0) {
            StringBuilder temp = new StringBuilder(Integer.toHexString(i));
            while (temp.length() < 8) {
                temp.insert(0, 0);
            }
            result.append(temp);
        }
        return result.toString();
    }

    private static int sigma0(int x) {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3);
    }

    private static int sigma1(int x) {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >>> 10);
    }

    private static int Sigma0(int x) {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }

    private static int Sigma1(int x) {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }

    private static int Ch(int x, int y, int z) {
        return (y & x) | (z & ~x);
    }

    private static int Maj(int x, int y, int z) {
        return (x | y) & (z | (x & y));
    }
}
