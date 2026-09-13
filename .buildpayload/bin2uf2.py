"""RP2040 UF2: https://github.com/microsoft/uf2. Preserves the final 16 KiB (profiles + BTstack TLV)."""
import struct
FLASH_LIMIT=2*1024*1024-16384
def convert(binary):
    if not binary or len(binary)>FLASH_LIMIT: raise ValueError('Invalid binary size or overlap with profile/Bluetooth storage')
    blocks=[];count=(len(binary)+255)//256
    for i in range(count):
        header=struct.pack('<8I',0x0A324655,0x9E5D5157,0x2000,0x10000000+i*256,256,i,count,0xE48BFF56)
        blocks.append(header+binary[i*256:(i+1)*256].ljust(256,b'\0')+bytes(220)+struct.pack('<I',0x0AB16F30))
    return b''.join(blocks)
