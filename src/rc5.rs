use {
  crate::{error::Error, word::Word},
  num::integer::div_ceil,
  std::{cmp::max, mem::size_of},
};

pub fn encode<W: Word>(
  key: &[u8],
  plaintext: &[u8],
  rounds: usize,
) -> Result<Vec<u8>, Error> {
  let word_bytes = size_of::<W>();
  let block_size = 2 * word_bytes;

  if plaintext.len() % block_size != 0 {
    return Err(Error::InvalidPlaintextLength);
  }

  let expanded_key = expand_key::<W>(&key, rounds)?;
  let mut ciphertext = Vec::with_capacity(plaintext.len());
  for block in plaintext.chunks(block_size) {
    let block = [
      W::from_le_bytes(&block[0..word_bytes])?,
      W::from_le_bytes(&block[word_bytes..block_size])?,
    ];

    ciphertext.extend(
      decode_block::<W>(&expanded_key, block)?
        .into_iter()
        .map(|w| w.to_le_bytes())
        .flatten(),
    );
  }

  Ok(ciphertext)
}

pub fn decode<W: Word>(
  key: &[u8],
  ciphertext: &[u8],
  rounds: usize,
) -> Result<Vec<u8>, Error> {
  let word_bytes = size_of::<W>();
  let block_size = 2 * word_bytes;

  if ciphertext.len() % block_size != 0 {
    return Err(Error::InvalidCipherTextLength);
  }

  let mut plaintext = Vec::with_capacity(ciphertext.len());
  let expanded_key = expand_key::<W>(&key, rounds)?;
  for block in ciphertext.chunks(block_size) {
    let block = [
      W::from_le_bytes(&block[0..word_bytes])?,
      W::from_le_bytes(&block[word_bytes..block_size])?,
    ];

    plaintext.extend(
      encode_block::<W>(&expanded_key, block)?
        .into_iter()
        .map(|w| w.to_le_bytes())
        .flatten(),
    );
  }

  Ok(plaintext)
}

fn decode_block<W: Word>(
  expanded_key: &[W],
  mut block: [W; 2],
) -> Result<[W; 2], Error> {
  let num_rounds = (expanded_key.len() / 2) - 1;
  block[0] = block[0].wrapping_add(&expanded_key[0]);
  block[1] = block[1].wrapping_add(&expanded_key[1]);

  for i in 1..=num_rounds {
    let rotation = block[1].to_u128().ok_or(Error::InvalidWordSize)?
      % W::NUMBER_OF_BITS as u128;
    block[0] = (block[0].bitxor(block[1]))
      .rotate_left(rotation as u32)
      .wrapping_add(&expanded_key[2 * i]);

    let rotation = block[0].to_u128().ok_or(Error::InvalidWordSize)?
      % W::NUMBER_OF_BITS as u128;
    block[1] = (block[1].bitxor(block[0]))
      .rotate_left(rotation as u32)
      .wrapping_add(&expanded_key[2 * i + 1]);
  }

  Ok(block)
}

fn encode_block<W: Word>(
  expanded_key: &[W],
  mut block: [W; 2],
) -> Result<[W; 2], Error> {
  let num_rounds = (expanded_key.len() / 2) - 1;

  for i in (1..=num_rounds).rev() {
    let rotation = block[0].to_u128().ok_or(Error::InvalidWordSize)?
      % W::NUMBER_OF_BITS as u128;

    block[1] = (block[1].wrapping_sub(&expanded_key[2 * i + 1]))
      .rotate_right(rotation as u32)
      .bitxor(block[0]);

    let rotation = block[1].to_u128().ok_or(Error::InvalidWordSize)?
      % W::NUMBER_OF_BITS as u128;
    block[0] = (block[0].wrapping_sub(&expanded_key[2 * i]))
      .rotate_right(rotation as u32)
      .bitxor(block[1]);
  }

  block[1] = block[1].wrapping_sub(&expanded_key[1]);
  block[0] = block[0].wrapping_sub(&expanded_key[0]);

  Ok(block)
}

pub fn expand_key<W: Word>(key: &[u8], rounds: usize) -> Result<Vec<W>, Error> {
  const MAX_ROUNDS: usize = 256;
  const MAX_KEY_SIZE: usize = 256;

  if key.len() > MAX_KEY_SIZE {
    return Err(Error::InvalidKeySize);
  }

  if rounds > MAX_ROUNDS {
    return Err(Error::InvalidRoundsCount);
  }

  let mut words: Vec<W> = convert_secret_key_to_words(key)?;

  let mut subkeys: Vec<W> = initialize_subkeys(rounds);

  let mut i = 0;
  let mut j = 0;
  let mut a = W::ZERO;
  let mut b = W::ZERO;

  let iters = max(subkeys.len(), words.len()) * 3;

  for _ in 0..iters {
    subkeys[i] = subkeys[i].wrapping_add(&a).wrapping_add(&b).rotate_left(3);
    a = subkeys[i];

    let rotation =
      a.wrapping_add(&b).to_u128().ok_or(Error::InvalidWordSize)?
        % W::NUMBER_OF_BITS as u128;

    words[j] = words[j]
      .wrapping_add(&a)
      .wrapping_add(&b)
      .rotate_left(rotation as u32);
    b = words[j];

    i = (i + 1) % subkeys.len();
    j = (j + 1) % words.len();
  }

  Ok(subkeys)
}

fn convert_secret_key_to_words<W: Word>(key: &[u8]) -> Result<Vec<W>, Error> {
  let words_len = div_ceil(max(key.len(), 1), size_of::<W>());
  let mut words = vec![W::ZERO; words_len];
  for i in (0..key.len()).rev() {
    let word_index = i / size_of::<W>();
    let word = W::from(key[i]).ok_or(Error::InvalidKey)?;
    words[word_index] = words[word_index].rotate_left(8).wrapping_add(&word);
  }
  Ok(words)
}

fn initialize_subkeys<W: Word>(rounds: usize) -> Vec<W> {
  let subkey_count = 2 * (rounds + 1);
  let mut subkeys = vec![W::zero(); subkey_count];

  subkeys[0] = W::P;
  for i in 1..subkey_count {
    subkeys[i] = subkeys[i - 1].wrapping_add(&W::Q);
  }

  subkeys
}
