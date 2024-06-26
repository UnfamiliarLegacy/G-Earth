package gearth.protocol.crypto;
/*
 * Copyright (C) 2003 Clarence Ho (clarence@clarenceho.net)
 * All rights reserved.
 *
 * Redistribution and use of this software for non-profit, educational,
 * or persoanl purposes, in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * In case of using this software for other purposes not stated above,
 * please conact Clarence Ho (clarence@clarenceho.net) for permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CLARENCE HO "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

import java.util.Arrays;

/**
 * This is a simple implementation of the RC4 (tm) encryption algorithm.  The
 * author implemented this class for some simple applications
 * that don't need/want/require the Sun's JCE framework.
 * <p>
 * But if you are looking for encryption algorithms for a
 * full-blown application,
 * it would be better to stick with Sun's JCE framework.  You can find
 * a *free* JCE implementation with RC4 (tm) at
 * Cryptix (http://www.cryptix.org/).
 * <p>
 * Note that RC4 (tm) is a trademark of RSA Data Security, Inc.
 * Also, if you are within USA, you may need to acquire licenses from
 * RSA to use RC4.
 * Please check your local law.  The author is not
 * responsible for any illegal use of this code.
 * <p>
 * @author  Clarence Ho
 */
public class RC4 implements RC4Cipher {

    private byte[] state = new byte[256];
    private int x;
    private int y;

    /**
     * Initializes the class with a string key. The length
     * of a normal key should be between 1 and 2048 bits.  But
     * this method doens't check the length at all.
     *
     * @param key   the encryption/decryption key
     */
    public RC4(String key) throws NullPointerException {
        this(key.getBytes());
    }

    /**
     * Initializes the class with a byte array key.  The length
     * of a normal key should be between 1 and 2048 bits.  But
     * this method doens't check the length at all.
     *
     * @param key   the encryption/decryption key
     */
    public RC4(byte[] key) throws NullPointerException {
        for (int i = 0; i < 256; i++) {
            state[i] = (byte) i;
        }

        x = 0;
        y = 0;

        int index1 = 0;
        int index2 = 0;

        byte tmp;

        if (key == null || key.length == 0) {
            throw new NullPointerException();
        }

        for (int i = 0; i < 256; i++) {
            index2 = ((key[index1] & 0xff) + (state[i] & 0xff) + index2) & 0xff;

            tmp = state[i];
            state[i] = state[index2];
            state[index2] = tmp;

            index1 = (index1 + 1) % key.length;
        }
    }

    public RC4(byte[] state, int x, int y) {
        this.x = x;
        this.y = y;
        this.state = state;
    }

    /**
     * RC4 encryption/decryption.
     *
     * @param data the data to be encrypted/decrypted
     * @return the result of the encryption/decryption
     */
    @Override
    public byte[] cipher(byte[] data) {
        return cipher(data, 0, data.length);
    }

    @Override
    public byte[] cipher(byte[] data, int offset, int length) {
        int xorIndex;
        byte tmp;

        if (data == null) {
            return null;
        }

        byte[] result = new byte[length];

        for (int i = 0; i < length; i++) {

            x = (x + 1) & 0xff;
            y = ((state[x] & 0xff) + y) & 0xff;

            tmp = state[x];
            state[x] = state[y];
            state[y] = tmp;

            xorIndex = ((state[x] & 0xff) + (state[y] & 0xff)) & 0xff;
            result[i] = (byte) (data[offset + i] ^ state[xorIndex]);
        }

        return result;
    }

    @Override
    public byte[] decipher(byte[] data) {
        return cipher(data);
    }

    @Override
    public byte[] decipher(byte[] data, int offset, int length) {
        return cipher(data, offset, length);
    }

    @Override
    public byte[] getState () {
        return state;
    }

    @Override
    public int getQ() {
        return x;
    }

    @Override
    public int getJ() {
        return y;
    }

    public RC4 deepCopy() {
        return new RC4(Arrays.copyOf(state, 256), x, y);
    }

    public boolean couldBeFresh() {
        return (x == 0 && y == 0);
    }

    public void undoRc4(byte[] buf) {
        byte tmp;

        for (int i = 0; i < buf.length; i++) {
            tmp = state[x];
            state[x] = state[y];
            state[y] = tmp;

            y = (y - (state[x] & 0xff)) & 0xff;
            x = (x - 1) & 0xff;
        }
    }
}