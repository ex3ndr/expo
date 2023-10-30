import { CodedError, TypedArray } from 'expo-modules-core';

import { CryptoDigestAlgorithm, CryptoEncoding, CryptoDigestOptions } from './Crypto.types';

const getCrypto = (): Crypto => window.crypto ?? (window as any).msCrypto;

export default {
  get name(): string {
    return 'ExpoCrypto';
  },
  async digestStringAsync(
    algorithm: CryptoDigestAlgorithm,
    data: string,
    options: CryptoDigestOptions
  ): Promise<string> {
    if (!crypto.subtle) {
      throw new CodedError(
        'ERR_CRYPTO_UNAVAILABLE',
        'Access to the WebCrypto API is restricted to secure origins (https).'
      );
    }
    const encoder = new TextEncoder();
    const buffer = encoder.encode(data);
    const hashedData = await crypto.subtle.digest(algorithm, buffer);
    if (options.encoding === CryptoEncoding.HEX) {
      return hexString(hashedData);
    } else if (options.encoding === CryptoEncoding.BASE64) {
      return btoa(String.fromCharCode(...new Uint8Array(hashedData)));
    }
    throw new CodedError('ERR_CRYPTO_DIGEST', 'Invalid encoding type provided.');
  },
  getRandomBytes(length: number): Uint8Array {
    const array = new Uint8Array(length);
    return getCrypto().getRandomValues(array);
  },
  async getRandomBytesAsync(length: number): Promise<Uint8Array> {
    const array = new Uint8Array(length);
    return getCrypto().getRandomValues(array);
  },
  getRandomValues(typedArray: TypedArray) {
    return getCrypto().getRandomValues(typedArray);
  },
  randomUUID() {
    return getCrypto().randomUUID();
  },
  digestAsync(algorithm: AlgorithmIdentifier, data: ArrayBuffer): Promise<ArrayBuffer> {
    return getCrypto().subtle.digest(algorithm, data);
  },
  async derivePBKDF2(algorithm: AlgorithmIdentifier, key: ArrayBuffer, salt: ArrayBuffer, iterations: number, length: number): Promise<ArrayBuffer> {
    if (!crypto.subtle) {
      throw new CodedError(
        'ERR_CRYPTO_UNAVAILABLE',
        'Access to the WebCrypto API is restricted to secure origins (https).'
      );
    }

    // Only subset of algorithms are supported
    if (algorithm !== 'SHA-1' && algorithm !== 'SHA-256' && algorithm !== 'SHA-512' && algorithm !== 'SHA-384') {
      throw new CodedError(
        'ERR_CRYPTO_UNSUPPORTED_ALGORITHM',
        'Unsupported algorithm provided.'
      );
    }

    // Import PBKDF2 base key
    const importedKey = await crypto.subtle.importKey('raw', key, 'PBKDF2', false, ['deriveBits']);

    // Derive bits
    let bits = length * 8; /* bit/byte variants are confusing and only multiplies of 8 works everywhere */
    return crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: algorithm }, importedKey, bits);
  }
};

function hexString(buffer: ArrayBuffer): string {
  const byteArray = new Uint8Array(buffer);

  const hexCodes = [...byteArray].map((value) => {
    const hexCode = value.toString(16);
    const paddedHexCode = hexCode.padStart(2, '0');
    return paddedHexCode;
  });

  return hexCodes.join('');
}
