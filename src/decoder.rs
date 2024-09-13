use std::{
    cmp::Ordering,
    collections::HashMap,
    io::{Cursor, Seek, SeekFrom},
};

use anyhow::anyhow;
use bytes::{Buf, Bytes};

use crate::Result;

const MAXIMUM_DATA_STRUCTURE_DEPTH: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
enum DataType {
    Extended = 0,
    Pointer,
    String,
    Float64,
    Bytes,
    Uint16,
    Uint32,
    Map,
    Int32,
    Uint64,
    Uint128,
    Slice,
    // We don't use the next two. They are placeholders. See the spec
    // for more details.
    Container, // nolint: deadcode, varcheck
    Marker,    // nolint: deadcode, varcheck
    Bool,
    Float32,
}

#[derive(Debug, Clone)]
pub enum Data {
    // Pointer(u64),
    String(String),
    Bytes(Bytes),
    Uint(u64),
    Float32(f32),
    Float64(f64),
    Map(HashMap<Bytes, Data>),
    Slice(Vec<Data>),
}

impl TryFrom<u8> for DataType {
    type Error = crate::Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        let data_type = match value {
            0 => Self::Extended,
            1 => Self::Pointer,
            2 => Self::String,
            3 => Self::Float64,
            4 => Self::Bytes,
            5 => Self::Uint16,
            6 => Self::Uint32,
            7 => Self::Map,
            8 => Self::Int32,
            9 => Self::Uint64,
            10 => Self::Uint128,
            11 => Self::Slice,
            12 => Self::Container,
            13 => Self::Marker,
            14 => Self::Bool,
            15 => Self::Float32,
            _ => return Err(anyhow!("unknown data type")),
        };

        Ok(data_type)
    }
}

#[derive(Debug)]
pub struct Decoder {
    buffer: Bytes,
}

impl Decoder {
    pub fn new(buffer: Bytes) -> Self {
        Decoder { buffer }
    }

    pub fn decode(&self, offset: u64) -> Result<(Data, u64)> {
        let (type_num, size, new_offset) = self.decode_ctl_data(offset)?;
        self.decode_from_type(type_num, size, new_offset)
    }

    fn decode_ctl_data(&self, offset: u64) -> Result<(DataType, u64, u64)> {
        let mut new_offset = offset + 1;
        if offset >= self.buffer.len() as u64 {
            return Err(anyhow!("unexpected end of database"));
        }

        let mut cursor = Cursor::new(&self.buffer);
        cursor.seek(SeekFrom::Start(offset))?;

        let ctrl_byte = cursor.get_u8();
        let mut type_num = DataType::try_from(ctrl_byte >> 5)?;
        if type_num == DataType::Extended {
            if new_offset >= self.buffer.len() as u64 {
                return Err(anyhow!("unexpected end of database"));
            }

            cursor.seek(SeekFrom::Start(new_offset))?;
            let b = cursor.get_u8();
            type_num = DataType::try_from(b + 7)?;
            new_offset += 1;
        }

        let (size, new_offet) = self.size_from_ctrl_byte(ctrl_byte, new_offset, type_num)?;
        Ok((type_num, size, new_offet))
    }

    fn size_from_ctrl_byte(
        &self,
        ctrl_byte: u8,
        offset: u64,
        type_num: DataType,
    ) -> Result<(u64, u64)> {
        let mut size = (ctrl_byte & 0x1f) as u64;
        if type_num == DataType::Extended {
            return Ok((size, offset));
        }

        if size < 29 {
            return Ok((size, offset));
        }

        let bytes_to_read = size - 28;
        let new_offset = offset + bytes_to_read;
        if new_offset > self.buffer.len() as u64 {
            return Err(anyhow!("unexpected end of database"));
        }

        let mut cursor = Cursor::new(&self.buffer);
        if size == 29 {
            cursor.seek(SeekFrom::Start(offset))?;
            let size = 29 + cursor.get_u8() as u64;
            return Ok((size, offset + 1));
        }

        let size_bytes = &self.buffer.slice(offset as usize..new_offset as usize);

        match size.cmp(&30) {
            Ordering::Equal => {
                size = 285 + uint_from_bytes(0, size_bytes);
            }
            Ordering::Greater => {
                size = uint_from_bytes(0, size_bytes) + 65821;
            }
            Ordering::Less => {}
        }

        Ok((size, new_offset))
    }

    fn decode_from_type(&self, dtype: DataType, size: u64, offset: u64) -> Result<(Data, u64)> {
        let (data, offset) = match dtype {
            DataType::Map => {
                let (map, offset) = self.decode_map(size, offset)?;
                (Data::Map(map), offset)
            }
            DataType::Pointer => {
                let (pointer, new_offset) = self.decode_pointer(size, offset)?;
                let (value, _offset) = self.decode(pointer)?;
                (value, new_offset)
            }
            DataType::Slice => {
                let (value, new_offset) = self.decode_slice(size, offset)?;
                (Data::Slice(value), new_offset)
            }
            DataType::Bytes => {
                let (value, new_offset) = self.decode_bytes(size, offset);
                (Data::Bytes(value), new_offset)
            }
            DataType::String => {
                let (value, new_offset) = self.decode_string(size, offset);
                (Data::String(value), new_offset)
            }
            DataType::Uint16 => {
                let (value, new_offset) = self.decode_uint(size, offset);
                (Data::Uint(value), new_offset)
            }
            DataType::Uint32 => {
                let (value, new_offset) = self.decode_uint(size, offset);
                (Data::Uint(value), new_offset)
            }
            DataType::Uint64 => {
                let (value, new_offset) = self.decode_uint(size, offset);
                (Data::Uint(value), new_offset)
            }
            DataType::Float32 => {
                let (value, new_offset) = self.decode_float32(size, offset);
                (Data::Float32(value), new_offset)
            }
            DataType::Float64 => {
                let (value, new_offset) = self.decode_float64(size, offset);
                (Data::Float64(value), new_offset)
            }
            _ => {
                return Err(anyhow!("not support type: {:?}", dtype));
            }
        };

        Ok((data, offset))
    }

    fn decode_bool(&self, size: u64, offset: u64) -> (bool, u64) {
        (size != 0, offset)
    }

    fn decode_bytes(&self, size: u64, offset: u64) -> (Bytes, u64) {
        let new_offset = offset + size;
        (
            self.buffer.slice(offset as usize..new_offset as usize),
            new_offset,
        )
    }

    fn decode_string(&self, size: u64, offset: u64) -> (String, u64) {
        let new_offset = offset + size;
        let bs = self.buffer.slice(offset as usize..new_offset as usize);
        let s = unsafe { String::from_utf8_unchecked(bs.to_vec()) };

        (s, new_offset)
    }

    fn decode_float64(&self, size: u64, offset: u64) -> (f64, u64) {
        let new_offset = offset + size;
        let mut bs = self.buffer.slice(offset as usize..new_offset as usize);
        let bits = bs.get_u64();

        let value = f64::from_bits(bits);
        (value, new_offset)
    }

    fn decode_float32(&self, size: u64, offset: u64) -> (f32, u64) {
        let new_offset = offset + size;
        let mut bs = self.buffer.slice(offset as usize..new_offset as usize);
        let bits = bs.get_u32();

        let value = f32::from_bits(bits);
        (value, new_offset)
    }

    fn decode_uint(&self, size: u64, offset: u64) -> (u64, u64) {
        let new_offset = offset + size;
        let ubytes = self.buffer.slice(offset as usize..new_offset as usize);
        (uint_from_bytes(0, &ubytes), new_offset)
    }

    fn decode_pointer(&self, size: u64, offset: u64) -> Result<(u64, u64)> {
        let pointer_size = ((size >> 3) & 0x3) + 1;
        let new_offset = offset + pointer_size;
        if new_offset > self.buffer.len() as u64 {
            return Err(anyhow!("unexpected end of database"));
        }

        let pointer_bytes = self.buffer.slice(offset as usize..new_offset as usize);
        let prefix = if pointer_size == 4 { 0 } else { size & 0x7 };
        let unpacked = uint_from_bytes(prefix, &pointer_bytes);

        let pointer_value_offset = match pointer_size {
            1 => 0,
            2 => 2048,
            3 => 526336,
            4 => 0,
            _ => 0,
        };

        let pointer = unpacked + pointer_value_offset;
        Ok((pointer, new_offset))
    }

    fn decode_map(&self, size: u64, mut offset: u64) -> Result<(HashMap<Bytes, Data>, u64)> {
        let mut map = HashMap::new();

        for _i in 0..size {
            let (key, new_offset) = self.decode_key(offset)?;
            offset = new_offset;

            let (value, new_offset) = self.decode(offset)?;
            offset = new_offset;

            map.insert(key, value);
        }

        Ok((map, offset))
    }

    fn decode_slice(&self, size: u64, mut offset: u64) -> Result<(Vec<Data>, u64)> {
        let mut v = Vec::with_capacity(size as usize);

        for _i in 0..size {
            let (value, new_offset) = self.decode(offset)?;
            offset = new_offset;

            v.push(value);
        }

        Ok((v, offset))
    }

    fn decode_key(&self, offset: u64) -> Result<(Bytes, u64)> {
        let (type_num, size, data_offset) = self.decode_ctl_data(offset)?;
        if type_num == DataType::Pointer {
            let (pointer, ptr_offset) = self.decode_pointer(size, data_offset)?;
            let (key, _) = self.decode_key(pointer)?;

            return Ok((key, ptr_offset));
        }

        if type_num != DataType::String {
            return Err(anyhow!(
                "unexpected type when decoding string: {:?}",
                type_num
            ));
        }

        let new_offset = data_offset + size;
        if new_offset > self.buffer.len() as u64 {
            return Err(anyhow!("unexpected end of database"));
        }

        let key = self.buffer.slice(data_offset as usize..new_offset as usize);
        Ok((key, new_offset))
    }

    fn next_value_offset(&self, offset: u64, mut number_to_skip: u64) -> Result<u64> {
        if number_to_skip == 0 {
            return Ok(offset);
        }

        let (type_num, size, mut offset) = self.decode_ctl_data(offset)?;
        match type_num {
            DataType::Pointer => {
                (_, offset) = self.decode_pointer(size, offset)?;
            }
            DataType::Map => number_to_skip += 2 * size,
            DataType::Slice => number_to_skip += size,
            DataType::Bool => {}
            _ => offset += size,
        }

        self.next_value_offset(offset, number_to_skip - 1)
    }
}

fn uint_from_bytes(prefix: u64, ubytes: &[u8]) -> u64 {
    let mut val = prefix;
    for &b in ubytes {
        val = (val << 8) | b as u64;
    }

    val
}
