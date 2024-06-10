pub mod error;
pub mod rc5;
pub mod word;

pub use rc5::{decode, encode};

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn encode_a() {
    let key = vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F,
    ];
    let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
    let res = encode::<u32>(&key, &pt, 12).unwrap();
    assert!(&ct[..] == &res[..]);
  }

  #[test]
  fn encode_b() {
    let key = vec![
      0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10,
      0x48, 0x81, 0xFF, 0x48,
    ];
    let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
    let res = encode::<u32>(&key, &pt, 12).unwrap();
    assert!(&ct[..] == &res[..]);
  }

  #[test]
  fn decode_a() {
    let key = vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F,
    ];
    let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
    let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let res = decode::<u32>(&key, &ct, 12).unwrap();
    assert!(&pt[..] == &res[..]);
  }

  #[test]
  fn decode_b() {
    let key = vec![
      0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10,
      0x48, 0x81, 0xFF, 0x48,
    ];
    let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
    let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    let res = decode::<u32>(&key, &ct, 12).unwrap();
    assert!(&pt[..] == &res[..]);
  }

  #[test]
  fn encode_16_16_8() {
    let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let pt = vec![0x00, 0x01, 0x02, 0x03];
    let ct = vec![0x23, 0xA8, 0xD7, 0x2E];

    let res = encode::<u16>(&key, &pt, 16).unwrap();
    assert!(&ct[..] == &res[..]);
  }

  #[test]
  fn encode_32_20_16() {
    let key = vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F,
    ];

    let pt = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let ct = vec![0x2a, 0x0e, 0xdc, 0x0e, 0x94, 0x31, 0xff, 0x73];

    let res = encode::<u32>(&key, &pt, 20).unwrap();
    assert!(&ct[..] == &res[..]);
  }

  #[test]
  fn encode_64_24_24() {
    let key = vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    ];

    let pt = vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F,
    ];
    let ct = vec![
      0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32,
      0xAE, 0x71, 0x78, 0xDA,
    ];

    let res = encode::<u64>(&key, &pt, 24).unwrap();
    assert!(&ct[..] == &res[..]);
  }

  #[test]
  fn encode_128_28_32() {
    let key = vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];

    let pt = vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    ];

    let ct = vec![
      0xEC, 0xA5, 0x91, 0x09, 0x21, 0xA4, 0xF4, 0xCF, 0xDD, 0x7A, 0xD7, 0xAD,
      0x20, 0xA1, 0xFC, 0xBA, 0x06, 0x8E, 0xC7, 0xA7, 0xCD, 0x75, 0x2D, 0x68,
      0xFE, 0x91, 0x4B, 0x7F, 0xE1, 0x80, 0xB4, 0x40,
    ];

    let res = encode::<u128>(&key, &pt, 28).unwrap();
    assert!(&ct[..] == &res[..]);
  }
}
