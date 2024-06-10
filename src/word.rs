use {
    crate::error::Error,
    num::{
        traits::{WrappingAdd, WrappingSub},
        PrimInt,
    },
    std::{mem::size_of, ops::BitXor},
};

pub trait Word: BitXor + WrappingAdd + WrappingSub + PrimInt
where
    Self: Sized,
{
    const BITS_PER_BYTE: usize = 8;
    const NUMBER_OF_BITS: usize = size_of::<Self>() * Self::BITS_PER_BYTE;

    const P: Self;
    const Q: Self;
    const ZERO: Self;

    fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error>;
    fn to_le_bytes(&self) -> Vec<u8>;
}

impl Word for u16 {
    const Q: Self = 0x9e37;
    const P: Self = 0xb7e1;
    const ZERO: Self = 0;

    fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != size_of::<Self>() {
            return Err(Error::InvalidBytes);
        }

        Ok(u16::from_le_bytes(
            bytes.try_into().map_err(|_| Error::InvalidBytes)?,
        ))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        u16::to_le_bytes(*self).to_vec()
    }
}

impl Word for u32 {
    const Q: Self = 0x9E3779B9;
    const P: Self = 0xb7e15163;
    const ZERO: Self = 0;

    fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != size_of::<Self>() {
            return Err(Error::InvalidBytes);
        }

        Ok(u32::from_le_bytes(bytes.try_into()?))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        u32::to_le_bytes(*self).to_vec()
    }
}

impl Word for u64 {
    const Q: Self = 0x9E3779B97F4A7C15;
    const P: Self = 0xB7E151628AED2A6B;
    const ZERO: Self = 0;

    fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != size_of::<Self>() {
            return Err(Error::InvalidBytes);
        }

        Ok(u64::from_le_bytes(bytes.try_into()?))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        u64::to_le_bytes(*self).to_vec()
    }
}

impl Word for u128 {
    const Q: Self = 0x9E3779B97F4A7C15F39CC0605CEDC835;
    const P: Self = 0xB7E151628AED2A6ABF7158809CF4F3C7;
    const ZERO: Self = 0;

    fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != size_of::<Self>() {
            return Err(Error::InvalidBytes);
        }

        Ok(u128::from_le_bytes(bytes.try_into()?))
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        u128::to_le_bytes(*self).to_vec()
    }
}
