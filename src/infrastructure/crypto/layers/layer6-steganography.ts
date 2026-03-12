/**
 * Layer 6: Steganography
 * Técnicas de esteganografía para ocultar datos
 */

import pako from 'pako';

/**
 * LSBSteganography - Least Significant Bit steganography
 * Oculta datos en los bits menos significativos de imágenes
 */
export class LSBSteganography {
  /**
   * Ocultar mensaje en datos binarios
   */
  async embed(data: string, carrier: Uint8Array): Promise<Uint8Array> {
    const binaryData = this.stringToBinary(data);
    const binaryLength = binaryData.length.toString(2).padStart(32, '0');
    
    // Verificar capacidad
    if (binaryLength.length + binaryData.length > carrier.length * 8) {
      throw new Error('Carrier too small for data');
    }
    
    const result = new Uint8Array(carrier);
    let bitIndex = 0;
    
    // Escribir longitud primero (32 bits)
    for (let i = 0; i < 32 && i < binaryLength.length; i++) {
      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = 7 - (bitIndex % 8);
      
      if (byteIndex < result.length) {
        result[byteIndex] = (result[byteIndex] & 0xFE) | parseInt(binaryLength[i], 10);
        bitIndex++;
      }
    }
    
    // Escribir datos
    for (let i = 0; i < binaryData.length; i++) {
      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = 7 - (bitIndex % 8);
      
      if (byteIndex < result.length) {
        result[byteIndex] = (result[byteIndex] & 0xFE) | parseInt(binaryData[i], 10);
        bitIndex++;
      }
    }
    
    return result;
  }

  /**
   * Extraer mensaje de datos
   */
  async extract(carrier: Uint8Array): Promise<string> {
    let binary = '';
    let bitIndex = 0;
    
    // Leer longitud (32 bits)
    for (let i = 0; i < 32; i++) {
      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = 7 - (bitIndex % 8);
      
      if (byteIndex < carrier.length) {
        binary += ((carrier[byteIndex] >> bitPosition) & 1).toString();
        bitIndex++;
      }
    }
    
    const length = parseInt(binary, 2);
    
    // Leer datos
    binary = '';
    for (let i = 0; i < length; i++) {
      const byteIndex = Math.floor(bitIndex / 8);
      const bitPosition = 7 - (bitIndex % 8);
      
      if (byteIndex < carrier.length) {
        binary += ((carrier[byteIndex] >> bitPosition) & 1).toString();
        bitIndex++;
      }
    }
    
    return this.binaryToString(binary);
  }

  private stringToBinary(str: string): string {
    return str.split('').map(char => 
      char.charCodeAt(0).toString(2).padStart(8, '0')
    ).join('');
  }

  private binaryToString(binary: string): string {
    const bytes = binary.match(/.{1,8}/g) || [];
    return bytes.map(byte => String.fromCharCode(parseInt(byte, 2))).join('');
  }
}

/**
 * SecureCompression - Compresión segura de datos
 */
export class SecureCompression {
  /**
   * Comprimir datos con algoritmo seguro
   */
  async compress(data: Uint8Array): Promise<Uint8Array> {
    const compressed = pako.deflate(data, { level: 9 });
    return new Uint8Array(compressed);
  }

  /**
   * Descomprimir datos
   */
  async decompress(data: Uint8Array): Promise<Uint8Array> {
    const decompressed = pako.inflate(data);
    return new Uint8Array(decompressed);
  }

  /**
   * Comprimir y verificar integridad
   */
  async compressWithChecksum(data: Uint8Array): Promise<Uint8Array> {
    // Calcular checksum primero
    const checksum = this.calculateChecksum(data);
    
    // Combinar datos + checksum
    const combined = new Uint8Array(data.length + 4);
    combined.set(data, 0);
    combined.set(new Uint8Array([checksum >>> 24, (checksum >>> 16) & 0xFF, (checksum >>> 8) & 0xFF, checksum & 0xFF]), data.length);
    
    // Comprimir
    return this.compress(combined);
  }

  /**
   * Descomprimir y verificar integridad
   */
  async decompressWithChecksum(data: Uint8Array): Promise<Uint8Array> {
    // Descomprimir
    const decompressed = await this.decompress(data);
    
    // Extraer checksum y datos
    const checksum = (decompressed[decompressed.length - 4] << 24) |
                     (decompressed[decompressed.length - 3] << 16) |
                     (decompressed[decompressed.length - 2] << 8) |
                     decompressed[decompressed.length - 1];
    
    const originalData = decompressed.slice(0, -4);
    
    // Verificar
    const calculatedChecksum = this.calculateChecksum(originalData);
    if (checksum !== calculatedChecksum) {
      throw new Error('Checksum verification failed');
    }
    
    return originalData;
  }

  private calculateChecksum(data: Uint8Array): number {
    let checksum = 0;
    for (let i = 0; i < data.length; i++) {
      checksum = ((checksum << 5) - checksum) + data[i];
      checksum = checksum & checksum; // Keep 32-bit
    }
    return checksum >>> 0;
  }
}
