pub use chacha20::LegacyNonce;

use crate::{Key, Tag};
use aead::{
    consts::{U0, U16, U32, U8},
    AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser,
};
use chacha20::ChaCha20Legacy;
use cipher::KeyIvInit;
use zeroize::Zeroize;

use aead::generic_array::GenericArray;
use cipher::{StreamCipher, StreamCipherSeek};
use poly1305::{universal_hash::UniversalHash, Block, Poly1305};
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
    fn new(key: &Key) -> Self {
        ChaCha20Poly1305Legacy { key: *key }
    }
}

impl AeadCore for ChaCha20Poly1305Legacy {
    type NonceSize = U8;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for ChaCha20Poly1305Legacy {
    fn encrypt_in_place_detached(
        &self,
        nonce: &LegacyNonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        Cipher::new(ChaCha20Legacy::new(&self.key, nonce))
            .encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &LegacyNonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        Cipher::new(ChaCha20Legacy::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

impl Drop for ChaCha20Poly1305Legacy {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

/// Size of a ChaCha20 block in bytes
const BLOCK_SIZE: usize = 64;

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
const MAX_BLOCKS: usize = core::u32::MAX as usize; // TODO

/// ChaCha20Poly1305 instantiated with a particular nonce
pub(crate) struct Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    cipher: C,
    mac: BufferedPoly1305,
}

impl<C> Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    /// Instantiate the underlying cipher with a particular nonce
    pub(crate) fn new(mut cipher: C) -> Self {
        // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut mac_key);
        let mac = BufferedPoly1305::new(GenericArray::from_slice(&mac_key));
        mac_key.zeroize();

        // Set ChaCha20 counter to 1
        cipher.seek(BLOCK_SIZE as u64);

        Self { cipher, mac }
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub(crate) fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        // TODO(tarcieri): interleave encryption with Poly1305
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        self.cipher.apply_keystream(buffer);

        self.mac.update_buffered(associated_data);
        self.mac
            .update_buffered(&(associated_data.len() as u64).to_le_bytes());
        self.mac.update_buffered(buffer);
        self.mac
            .update_buffered(&(buffer.len() as u64).to_le_bytes());

        Ok(self.mac.finalize())
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub(crate) fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_buffered(associated_data);
        self.mac
            .update_buffered(&(associated_data.len() as u64).to_le_bytes());
        self.mac.update_buffered(buffer);
        self.mac
            .update_buffered(&(buffer.len() as u64).to_le_bytes());

        let expected_tag = self.mac.finalize();

        // This performs a constant-time comparison using the `subtle` crate
        if expected_tag.ct_eq(tag).unwrap_u8() == 1 {
            // TODO(tarcieri): interleave decryption with Poly1305
            // See: <https://github.com/RustCrypto/AEADs/issues/74>
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(Error)
        }
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
