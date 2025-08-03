use crate::{Key, Tag};
use aead::{
    self, AeadCore, AeadInOut, Error, KeyInit, KeySizeUser, TagPosition,
    array::{Array, ArraySize},
    consts,
    consts::{U8, U16, U32},
    inout::InOutBuf,
};
use chacha20::{ChaCha20Legacy, LegacyNonce};
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::{Poly1305, universal_hash::UniversalHash};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct ChaCha20Poly1305Legacy {
    /// Secret key
    key: Key,
}

impl KeySizeUser for ChaCha20Poly1305Legacy {
    type KeySize = U32;
}

impl KeyInit for ChaCha20Poly1305Legacy {
    #[inline]
    fn new(key: &Key) -> Self {
        Self { key: *key }
    }
}

impl AeadCore for ChaCha20Poly1305Legacy {
    type NonceSize = U8;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for ChaCha20Poly1305Legacy {
    fn encrypt_inout_detached(
        &self,
        nonce: &LegacyNonce,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag, Error> {
        let (mut cipher, mut mac) = self.init_cipher(nonce);

        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        // TODO(tarcieri): interleave encryption with Poly1305
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        cipher.apply_keystream_inout(buffer.reborrow());

        mac.update_buffered(associated_data);
        mac.update_buffered(&(associated_data.len() as u64).to_le_bytes());
        mac.update_buffered(buffer.get_out());
        mac.update_buffered(&(buffer.len() as u64).to_le_bytes());

        Ok(mac.finalize())
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &LegacyNonce,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag,
    ) -> Result<(), Error> {
        let (mut cipher, mut mac) = self.init_cipher(nonce);

        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        mac.update_buffered(associated_data);
        mac.update_buffered(&(associated_data.len() as u64).to_le_bytes());
        mac.update_buffered(buffer.get_in());
        mac.update_buffered(&(buffer.len() as u64).to_le_bytes());

        let expected_tag = mac.finalize();

        // This performs a constant-time comparison using the `subtle` crate
        if expected_tag.ct_eq(tag).unwrap_u8() == 1 {
            // TODO(tarcieri): interleave decryption with Poly1305
            // See: <https://github.com/RustCrypto/AEADs/issues/74>
            cipher.apply_keystream_inout(buffer);
            Ok(())
        } else {
            Err(Error)
        }

        // // This performs a constant-time comparison using the `subtle` crate
        // if self.mac.verify(tag).is_ok() {
        //     // TODO(tarcieri): interleave decryption with Poly1305
        //     // See: <https://github.com/RustCrypto/AEADs/issues/74>
        //     self.cipher.apply_keystream_inout(buffer);
        //     Ok(())
        // } else {
        //     Err(Error)
        // }
    }
}

impl Drop for ChaCha20Poly1305Legacy {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.key.as_mut_slice().zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for ChaCha20Poly1305Legacy {}

/// Size of a ChaCha20 block in bytes
const BLOCK_SIZE: usize = 64;

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
const MAX_BLOCKS: usize = u32::MAX as usize;

impl ChaCha20Poly1305Legacy {
    fn init_cipher(&self, nonce: &LegacyNonce) -> (ChaCha20Legacy, BufferedPoly1305) {
        let mut cipher = ChaCha20Legacy::new(&self.key, nonce);
        // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut mac_key);

        let mac = BufferedPoly1305::new(&mac_key);
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            mac_key.zeroize();
        }

        // Set ChaCha20 counter to 1
        cipher.seek(BLOCK_SIZE as u64);

        (cipher, mac)
    }
}

struct BufferedPoly1305 {
    poly1305: Poly1305,
    block_buffer: BlockBuffer,
}

impl BufferedPoly1305 {
    fn new(key: &poly1305::Key) -> Self {
        BufferedPoly1305 {
            poly1305: Poly1305::new(key),
            block_buffer: BlockBuffer::new(),
        }
    }

    fn update_buffered(&mut self, data: &[u8]) {
        if let Some((buffered_block, complete_blocks)) = self.block_buffer.add_slice(data) {
            self.poly1305.update(&[buffered_block]);
            self.poly1305.update_padded(complete_blocks); // TODO
        }
    }

    fn finalize(self) -> poly1305::Tag {
        self.poly1305
            .compute_unpadded(self.block_buffer.remainder())
    }
}

struct BlockBuffer {
    block: poly1305::Block,
    size: usize,
}

impl BlockBuffer {
    pub fn new() -> Self {
        Self {
            block: Default::default(),
            size: 0,
        }
    }

    pub fn add_slice<'a>(&mut self, data: &'a [u8]) -> Option<(poly1305::Block, &'a [u8])> {
        let rem_size = poly1305::BLOCK_SIZE - self.size;
        let start_idx = core::cmp::min(rem_size, data.len());

        self.block[self.size..self.size + start_idx].copy_from_slice(&data[..start_idx]);
        self.size += start_idx;

        match data.get(start_idx..) {
            Some(chunkable) if chunkable.len() > 0 => {
                let tail_split = chunkable.len() - chunkable.len() % poly1305::BLOCK_SIZE;
                let (body, tail) = chunkable.split_at(tail_split);

                let returned_block = self.block;

                self.block[..tail.len()].copy_from_slice(&tail);
                self.size = tail.len();

                Some((returned_block, body))
            }
            _ => None,
        }
    }

    pub fn remainder(&self) -> &[u8] {
        &self.block[..self.size]
    }
}
