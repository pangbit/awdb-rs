use core::str;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;

use anyhow::anyhow;
use bytes::{Buf, Bytes};
use memchr::memmem;

use crate::decoder::{Data, Decoder};
use crate::Result;

const METADATA_START_MARKER: &[u8; 16] = b"\xAB\xCD\xEFipplus360.com";
const DATA_SECTIONS_SEPARATOR_SIZE: u64 = 16;

#[derive(Debug, Default)]
struct Metadata {
    binary_format_major_version: u64,
    binary_format_minor_version: u64,
    build_epoch: u64,
    database_type: String,
    description: HashMap<String, String>,
    ip_version: u64,
    languages: Vec<String>,
    node_count: u64,
    record_size: u64,
}

impl Metadata {
    fn new(buffer: Bytes) -> Result<Self> {
        let decoder = Decoder::new(buffer);
        let (value, _) = decoder.decode(0)?;

        let mut metadata = Self::default();
        if let Data::Map(map) = value {
            for (k, v) in map {
                match str::from_utf8(&k) {
                    Err(_e) => {
                        return Err(anyhow!("invalid metadata key: {:?}", k));
                    }
                    Ok(k) => match k {
                        "binary_format_major_version" => {
                            if let Data::Uint(v) = v {
                                metadata.binary_format_major_version = v;
                            } else {
                                return Err(anyhow!(
                                    "invalid binary_format_major_version: {:?}",
                                    v
                                ));
                            }
                        }
                        "binary_format_minor_version" => {
                            if let Data::Uint(v) = v {
                                metadata.binary_format_minor_version = v;
                            } else {
                                return Err(anyhow!(
                                    "invalid binary_format_minor_version: {:?}",
                                    v
                                ));
                            }
                        }
                        "build_epoch" => {
                            if let Data::Uint(v) = v {
                                metadata.build_epoch = v;
                            } else {
                                return Err(anyhow!("invalid build_epoch: {:?}", v));
                            }
                        }
                        "database_type" => {
                            if let Data::String(v) = v {
                                metadata.database_type = v;
                            } else {
                                return Err(anyhow!("invalid database_type: {:?}", v));
                            }
                        }
                        "description" => {
                            if let Data::Map(v) = v {
                                for (dk, dv) in v {
                                    if let Ok(dk) = str::from_utf8(&dk) {
                                        if let Data::String(dv) = dv {
                                            metadata.description.insert(dk.to_string(), dv);
                                        } else {
                                            return Err(anyhow!(
                                                "invalid description val: {:?}",
                                                dv
                                            ));
                                        }
                                    } else {
                                        return Err(anyhow!("invalid description key: {:?}", dk));
                                    }
                                }
                            } else {
                                return Err(anyhow!("invalid description: {:?}", v));
                            }
                        }
                        "ip_version" => {
                            if let Data::Uint(v) = v {
                                metadata.ip_version = v;
                            } else {
                                return Err(anyhow!("invalid ip_version: {:?}", v));
                            }
                        }
                        "languages" => {
                            if let Data::Slice(v) = v {
                                for l in v {
                                    if let Data::String(l) = l {
                                        metadata.languages.push(l);
                                    } else {
                                        return Err(anyhow!("invalid language item: {:?}", l));
                                    }
                                }
                            } else {
                                return Err(anyhow!("invalid languages: {:?}", v));
                            }
                        }
                        "node_count" => {
                            if let Data::Uint(v) = v {
                                metadata.node_count = v;
                            } else {
                                return Err(anyhow!("invalid node_count: {:?}", v));
                            }
                        }
                        "record_size" => {
                            if let Data::Uint(v) = v {
                                metadata.record_size = v;
                            } else {
                                return Err(anyhow!("invalid record_size: {:?}", v));
                            }
                        }
                        _ => {}
                    },
                }
            }
        } else {
            return Err(anyhow!("unknown metadata: {:?}", value));
        }

        Ok(metadata)
    }
}

#[derive(Debug)]
struct NodeReader {
    buffer: Bytes,
}

impl NodeReader {
    fn new(buffer: Bytes) -> Self {
        Self { buffer }
    }

    fn read_left(&self, node_num: u64) -> Result<u64> {
        let mut cursor = Cursor::new(&self.buffer);

        cursor.seek(SeekFrom::Start(node_num))?;
        let b1 = cursor.get_u8() as u64;
        let b1 = b1 << 24;

        cursor.seek(SeekFrom::Start(node_num + 1))?;
        let b2 = cursor.get_u8() as u64;
        let b2 = b2 << 16;

        cursor.seek(SeekFrom::Start(node_num + 2))?;
        let b3 = cursor.get_u8() as u64;
        let b3 = b3 << 8;

        cursor.seek(SeekFrom::Start(node_num + 3))?;
        let b4 = cursor.get_u8() as u64;

        Ok(b1 | b2 | b3 | b4)
    }

    fn read_right(&self, node_num: u64) -> Result<u64> {
        let mut cursor = Cursor::new(&self.buffer);

        cursor.seek(SeekFrom::Start(node_num + 4))?;
        let b1 = cursor.get_u8() as u64;
        let b1 = b1 << 24;

        cursor.seek(SeekFrom::Start(node_num + 5))?;
        let b2 = cursor.get_u8() as u64;
        let b2 = b2 << 16;

        cursor.seek(SeekFrom::Start(node_num + 6))?;
        let b3 = cursor.get_u8() as u64;
        let b3 = b3 << 8;

        cursor.seek(SeekFrom::Start(node_num + 7))?;
        let b4 = cursor.get_u8() as u64;

        Ok(b1 | b2 | b3 | b4)
    }
}

#[derive(Debug)]
pub struct DB {
    buffer: Bytes,
    metadata: Metadata,

    node_reader: NodeReader,
    decoder: Decoder,

    ipv4_start: u64,
    ipv4_start_bit_depth: u64,
    node_offset_mult: u64,
}

impl DB {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let buffer = Bytes::from(fs::read(path)?);
        let pos = memmem::rfind(&buffer, METADATA_START_MARKER)
            .ok_or(anyhow!("not found metadata start marker"))?;

        let metadata_buffer = buffer.slice(pos + METADATA_START_MARKER.len()..);
        let metadata = Metadata::new(metadata_buffer)?;

        let search_tree_size = metadata.node_count * metadata.record_size / 4;
        let data_section_start = search_tree_size + DATA_SECTIONS_SEPARATOR_SIZE;
        let data_section_end = pos;

        let node_buffer = buffer.slice(..search_tree_size as usize);
        let node_reader = NodeReader::new(node_buffer);

        let ip_buffer = buffer.slice(data_section_start as usize..data_section_end as usize);
        let decoder = Decoder::new(ip_buffer);

        let node_offset_mult = metadata.record_size / 4;

        let mut db = Self {
            buffer,
            metadata,
            node_reader,
            decoder,
            ipv4_start: 0,
            ipv4_start_bit_depth: 0,
            node_offset_mult,
        };

        db.set_ipv4_start()?;
        Ok(db)
    }

    pub fn lookup(&self, ip: IpAddr) -> Result<HashMap<String, String>> {
        let data = self.lookup_raw(ip)?;

        if let Data::Map(map) = data {
            let mut smap = HashMap::with_capacity(map.len());
            for (k, v) in map {
                if let Ok(key) = String::from_utf8(k.to_vec()) {
                    match v {
                        Data::Bytes(bs) => {
                            if let Ok(val) = String::from_utf8(bs.to_vec()) {
                                let val = if val.is_empty() {
                                    "-1".to_string()
                                } else {
                                    val.replace("\"", "'")
                                };

                                smap.insert(key, val);
                            } else {
                                return Err(anyhow!(
                                    "lookup data.value is invalid utf8 string, {:?}",
                                    k
                                ));
                            }
                        }
                        Data::String(val) => {
                            let val = if val.is_empty() {
                                "-1".to_string()
                            } else {
                                val.replace("\"", "'")
                            };

                            smap.insert(key, val);
                        }
                        _ => return Err(anyhow!("unsupported lookup data.value type: {:?}", v)),
                    }
                } else {
                    return Err(anyhow!("lookup data.key is invalid utf8 string, {:?}", k));
                }
            }

            Ok(smap)
        } else {
            Err(anyhow!("unknown data type: {:?}", data))
        }
    }

    fn lookup_raw(&self, ip: IpAddr) -> Result<Data> {
        if self.buffer.is_empty() {
            return Err(anyhow!("cannot call lookup on a closed database"));
        }

        let (pointer, _, _) = self.lookup_pointer(ip)?;
        if pointer == 0 {
            return Err(anyhow!("pointer is zero"));
        }

        self.retrieve_data(pointer)
    }

    fn set_ipv4_start(&mut self) -> Result<()> {
        if self.metadata.ip_version != 6 {
            return Ok(());
        }

        let node_count = self.metadata.node_count;
        let mut node = 0;

        let mut i = 0;
        while i < 96 && node < node_count {
            node = self.node_reader.read_left(node * self.node_offset_mult)?;
            i += 1;
        }

        self.ipv4_start = node;
        self.ipv4_start_bit_depth = i;

        Ok(())
    }

    fn decode(&self, offset: u64) -> Result<Data> {
        let (data, _) = self.decoder.decode(offset)?;
        Ok(data)
    }

    fn lookup_pointer(&self, ip: IpAddr) -> Result<(u64, u64, IpAddr)> {
        let (bit_count, node) = if ip.is_ipv6() {
            if self.metadata.ip_version == 4 {
                return Err(anyhow!("error looking ip '{}': you attempted to look up an IPv6 address in an IPv4-only database", ip));
            }

            (16 * 8, 0)
        } else {
            (4 * 8, self.ipv4_start)
        };

        let (node, prefix_length) = self.traverse_tree(ip, node, bit_count)?;

        match node.cmp(&self.metadata.node_count) {
            Ordering::Equal => Ok((0, prefix_length, ip)),
            Ordering::Greater => Ok((node, prefix_length, ip)),
            Ordering::Less => Err(anyhow!("invalid node in search tree")),
        }
    }

    fn traverse_tree(&self, ip: IpAddr, mut node: u64, bit_count: u64) -> Result<(u64, u64)> {
        let node_count = self.metadata.node_count;
        let mut i = 0;

        let ip = match ip {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };

        while i < bit_count && node < node_count {
            let ipbit = ip
                .get(i as usize >> 3)
                .ok_or(anyhow!("ip bit out of index"))?;
            let bit = 1 & ((*ipbit as u64) >> (7 - (i % 8)));

            let offset = node * self.node_offset_mult;

            if bit == 0 {
                node = self.node_reader.read_left(offset)?;
            } else {
                node = self.node_reader.read_right(offset)?;
            }

            i += 1;
        }

        Ok((node, i))
    }

    fn retrieve_data(&self, pointer: u64) -> Result<Data> {
        let offset = self.resolve_data_pointer(pointer)?;

        self.decode(offset)
    }

    fn resolve_data_pointer(&self, pointer: u64) -> Result<u64> {
        let resolved = pointer - self.metadata.node_count - DATA_SECTIONS_SEPARATOR_SIZE;

        if resolved >= self.buffer.len() as u64 {
            Err(anyhow!("the aw DB file's search tree is corrupt"))
        } else {
            Ok(resolved)
        }
    }
}
