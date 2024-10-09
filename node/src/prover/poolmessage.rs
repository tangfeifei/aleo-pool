// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkOS library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use snarkvm::ledger::puzzle::Solution;
use snarkvm::prelude::*;

use ::bytes::{Buf, BufMut, BytesMut};
use anyhow::{anyhow, Result};
use std::{default::Default, io::Write};
use tokio_util::codec::{Decoder, Encoder};

use ::bytes::Bytes;
use tokio::task;

const MAXIMUM_MESSAGE_SIZE: usize = 512;

/// This object enables deferred deserialization / ahead-of-time serialization for objects that
/// take a while to deserialize / serialize, in order to allow these operations to be non-blocking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolData<T: FromBytes + ToBytes + Send + 'static> {
    Object(T),
    Buffer(Bytes),
}

impl<T: FromBytes + ToBytes + Send + 'static> PoolData<T> {
    pub async fn deserialize(self) -> Result<T> {
        match self {
            Self::Object(x) => Ok(x),
            Self::Buffer(bytes) => match task::spawn_blocking(move || T::from_bytes_le(&bytes)).await {
                Ok(x) => x,
                Err(err) => Err(err.into()),
            },
        }
    }

    pub fn deserialize_blocking(self) -> Result<T> {
        match self {
            Self::Object(x) => Ok(x),
            Self::Buffer(bytes) => T::from_bytes_le(&bytes),
        }
    }

    pub async fn serialize(self) -> Result<Bytes> {
        match self {
            Self::Object(x) => match task::spawn_blocking(move || x.to_bytes_le()).await {
                Ok(bytes) => bytes.map(|vec| vec.into()),
                Err(err) => Err(err.into()),
            },
            Self::Buffer(bytes) => Ok(bytes),
        }
    }

    pub fn serialize_blocking_into<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Object(x) => {
                let bytes = x.to_bytes_le()?;
                Ok(writer.write_all(&bytes)?)
            }
            Self::Buffer(bytes) => Ok(writer.write_all(bytes)?),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PoolMessageSC<N: Network> {
    /// ConnectAck := (is_accecpt, c_address, c_rate, worker_id)
    ConnectAck(bool, Address<N>, u32, u32),
    /// Notify := (block_height, target, blockhash)
    Notify(u64, u64, N::BlockHash),
    /// ShutDown := ()
    ShutDown,
    /// Pong
    Pong,
    /// Unused
    #[allow(unused)]
    Unused,
}
impl<N: Network> Default for PoolMessageSC<N> {
    fn default() -> Self {
        Self::Unused
    }
}

impl<N: Network> PoolMessageSC<N> {
    /// Returns the messge name
    #[inline]
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        match self {
            Self::ConnectAck(..) => "ConnectAck",
            Self::Notify(..) => "Notify",
            Self::ShutDown => "Shutdown",
            Self::Pong => "Pong",
            Self::Unused => "Unused",
        }
    }

    /// Returns the message ID.
    #[inline]
    pub fn id(&self) -> u8 {
        match self {
            Self::ConnectAck(..) => 0,
            Self::Notify(..) => 1,
            Self::ShutDown => 2,
            Self::Pong => 3,
            Self::Unused => 127,
        }
    }

    /// Returns the message data as bytes.
    #[inline]
    pub fn serialize_data_into<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::ConnectAck(accept_sign, c_address, c_rate, id) => match accept_sign {
                true => {
                    writer.write_all(&[1u8])?;
                    bincode::serialize_into(&mut *writer, c_address)?;
                    bincode::serialize_into(&mut *writer, c_rate)?;
                    bincode::serialize_into(&mut *writer, id)?;
                    Ok(())
                }
                false => {
                    writer.write_all(&[0u8])?;
                    bincode::serialize_into(&mut *writer, c_address)?;
                    bincode::serialize_into(&mut *writer, c_rate)?;
                    bincode::serialize_into(&mut *writer, id)?;
                    Ok(())
                }
            },
            Self::Notify(block_height, target, block_hash) => {
                bincode::serialize_into(&mut *writer, block_height)?;
                bincode::serialize_into(&mut *writer, target)?;
                writer.write_all(&block_hash.to_bytes_le()?)?;
                Ok(())
            }
            Self::ShutDown => Ok(()),
            Self::Pong => Ok(()),
            Self::Unused => Ok(()),
        }
    }

    /// Serializes the given message into bytes.
    #[inline]
    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<()> {
        bincode::serialize_into(&mut *writer, &self.id())?;
        self.serialize_data_into(writer)
    }

    /// Deserializes the given buffer into a message.
    #[inline]
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.is_empty() {
            return Err(anyhow!("Invalid message buffer"));
        }

        let (id, data) = (buffer[0], &buffer[1..]);

        let message = match id {
            0 => match data.is_empty() {
                true => return Err(anyhow!("Invalid message buffer")),
                false => match data[0] {
                    0 => Self::ConnectAck(
                        false,
                        bincode::deserialize(&data[1..=32])?,
                        bincode::deserialize(&data[33..=36])?,
                        bincode::deserialize(&data[37..=40])?,
                    ),
                    1 => Self::ConnectAck(
                        true,
                        bincode::deserialize(&data[1..=32])?,
                        bincode::deserialize(&data[33..=36])?,
                        bincode::deserialize(&data[37..=40])?,
                    ),
                    _ => return Err(anyhow!("Invalid 'ConnectAck' message: {:?} {:?}", buffer, data)),
                },
            },
            1 => Self::Notify(
                bincode::deserialize(&data[0..8])?,
                bincode::deserialize(&data[8..16])?,
                N::BlockHash::read_le(&data[16..])?,
            ),
            2 => match data.is_empty() {
                true => Self::ShutDown,
                false => return Err(anyhow!("Invalid 'ShutDown' message: {:?} {:?}", buffer, data)),
            },
            3 => match data.is_empty() {
                true => Self::Pong,
                false => return Err(anyhow!("Invalid 'Pong' message: {:?} {:?}", buffer, data)),
            },
            _ => return Err(anyhow!("Invalid message ID {}", id)),
        };

        Ok(message)
    }
}

impl<N: Network> Encoder<PoolMessageSC<N>> for PoolMessageSC<N> {
    type Error = anyhow::Error;

    fn encode(&mut self, message: PoolMessageSC<N>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&0u32.to_le_bytes());
        message.serialize_into(&mut dst.writer())?;
        let len_slice = (dst[4..].len() as u32).to_le_bytes();
        dst[..4].copy_from_slice(&len_slice);
        Ok(())
    }
}

impl<N: Network> Decoder for PoolMessageSC<N> {
    type Error = std::io::Error;
    type Item = PoolMessageSC<N>;

    fn decode(&mut self, source: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if source.len() < 4 {
            return Ok(None);
        }
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&source[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;
        // Check that the length is not too large to avoid a denial of
        // service attack where the node server runs out of memory.
        if length > MAXIMUM_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            ));
        }

        if source.len() < 4 + length {
            // The full message has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            source.reserve(4 + length - source.len());

            // We inform `Framed` that we need more bytes to form the next frame.
            return Ok(None);
        }

        // Convert the buffer to a message, or fail if it is not valid.
        let message = match PoolMessageSC::deserialize(&source[4..][..length]) {
            Ok(message) => Ok(Some(message)),
            Err(error) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        };

        // Use `advance` to modify the source such that it no longer contains this frame.
        source.advance(4 + length);

        message
    }
}
#[derive(Clone, Debug)]
pub enum PoolMessageCS<N: Network> {
    /// Connect := (type, address_type, version(major, minor, patch), name, address)
    Connect(u8, u8, u8, u8, u8, String, String),
    /// submit := (work_id, reserve, prover_solution)
    Submit(u32, u64, PoolData<Solution<N>>),
    /// DisConnect := (id)
    DisConnect(u32),
    /// Ping
    Ping,
    /// ReportHashRate 每分钟上报一次, 如rate_1m = (最近1分钟的solution数量 / 60)
    /// ReportHashRate := (work_id, rate_1m, rate_5m, rate_15m, rate_30m, rate_60m)
    ReportHashRate(u32, u32, u32, u32, u32, u32),
    // Unused
    #[allow(unused)]
    Unused,
}

impl<N: Network> Default for PoolMessageCS<N> {
    fn default() -> Self {
        Self::Unused
    }
}

impl<N: Network> PoolMessageCS<N> {
    /// Returns the messge name
    #[inline]
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        match self {
            Self::Connect(..) => "Connect",
            Self::Submit(..) => "Submit",
            Self::DisConnect(..) => "Disconnect",
            Self::Ping => "Ping",
            Self::ReportHashRate(..) => "ReportHashRate",
            Self::Unused => "Unused",
        }
    }

    /// Returns the message ID.
    pub fn id(&self) -> u8 {
        match self {
            Self::Connect(..) => 128,
            Self::Submit(..) => 129,
            Self::DisConnect(..) => 130,
            Self::Ping => 131,
            Self::ReportHashRate(..) => 132,
            Self::Unused => 255,
        }
    }

    /// Returns the message data as bytes.
    #[inline]
    pub fn serialize_data_into<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Connect(worker_type, address_type, v_major, v_minor, v_patch, custom_name, address) => {
                writer.write_all(&[*worker_type])?;
                writer.write_all(&[*address_type])?;
                writer.write_all(&[*v_major])?;
                writer.write_all(&[*v_minor])?;
                writer.write_all(&[*v_patch])?;
                let len = custom_name.len() as u8;
                writer.write_all(&[len])?;
                writer.write_all(custom_name.as_bytes())?;
                //bincode::serialize_into(&mut *writer, custom_name)?;
                //bincode::serialize_into(&mut *writer, address)?;
                writer.write_all(address.as_bytes())?;
                Ok(())
            }
            Self::Submit(worker_id, reserve, prover_solution) => {
                bincode::serialize_into(&mut *writer, worker_id)?;
                bincode::serialize_into(&mut *writer, reserve)?;
                prover_solution.serialize_blocking_into(writer)
            }
            Self::DisConnect(id) => {
                bincode::serialize_into(&mut *writer, id)?;
                Ok(())
            }
            Self::Ping => Ok(()),
            Self::ReportHashRate(worker_id, rate_1m, rate_5m, rate_15m, rate_30m, rate_60m) => {
                bincode::serialize_into(&mut *writer, worker_id)?;
                bincode::serialize_into(&mut *writer, rate_1m)?;
                bincode::serialize_into(&mut *writer, rate_5m)?;
                bincode::serialize_into(&mut *writer, rate_15m)?;
                bincode::serialize_into(&mut *writer, rate_30m)?;
                bincode::serialize_into(&mut *writer, rate_60m)?;
                Ok(())
            }
            Self::Unused => Ok(()),
        }
    }

    /// Serializes the given message into bytes.
    #[inline]
    pub fn serialize_into<W: Write>(&self, writer: &mut W) -> Result<()> {
        bincode::serialize_into(&mut *writer, &self.id())?;
        self.serialize_data_into(writer)
    }

    /// Deserializes the given buffer into a message.
    #[inline]
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        if buffer.is_empty() {
            return Err(anyhow!("Invalid message buffer"));
        }

        let (id, data) = (buffer[0], &buffer[1..]);

        let message = match id {
            128 => {
                let name_end = (6 + data[5]) as usize;
                Self::Connect(
                    data[0],
                    data[1],
                    data[2],
                    data[3],
                    data[4],
                    String::from_utf8((data[6..name_end]).to_vec())?,
                    String::from_utf8((data[name_end..]).to_vec())?,
                )
            }
            129 => Self::Submit(
                bincode::deserialize(&data[0..4])?,
                bincode::deserialize(&data[4..12])?,
                PoolData::Buffer(data[12..].to_vec().into()),
            ),
            130 => Self::DisConnect(bincode::deserialize(data)?),
            131 => match data.is_empty() {
                true => Self::Ping,
                false => return Err(anyhow!("Invalid 'Ping' message: {:?} {:?}", buffer, data)),
            },
            132 => Self::ReportHashRate(
                bincode::deserialize(&data[0..4])?,
                bincode::deserialize(&data[4..8])?,
                bincode::deserialize(&data[8..12])?,
                bincode::deserialize(&data[12..16])?,
                bincode::deserialize(&data[16..20])?,
                bincode::deserialize(&data[20..24])?,
            ),
            _ => return Err(anyhow!("Invalid message ID {}", id)),
        };

        Ok(message)
    }
}

impl<N: Network> Encoder<PoolMessageCS<N>> for PoolMessageCS<N> {
    type Error = anyhow::Error;

    fn encode(&mut self, message: PoolMessageCS<N>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&0u32.to_le_bytes());
        message.serialize_into(&mut dst.writer())?;
        let len_slice = (dst[4..].len() as u32).to_le_bytes();
        dst[..4].copy_from_slice(&len_slice);
        Ok(())
    }
}

impl<N: Network> Decoder for PoolMessageCS<N> {
    type Error = std::io::Error;
    type Item = PoolMessageCS<N>;

    fn decode(&mut self, source: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if source.len() < 4 {
            return Ok(None);
        }
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&source[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;
        // Check that the length is not too large to avoid a denial of
        // service attack where the node server runs out of memory.
        if length > MAXIMUM_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length),
            ));
        }

        if source.len() < 4 + length {
            // The full message has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            source.reserve(4 + length - source.len());

            // We inform `Framed` that we need more bytes to form the next frame.
            return Ok(None);
        }

        // Convert the buffer to a message, or fail if it is not valid.
        let message = match PoolMessageCS::deserialize(&source[4..][..length]) {
            Ok(message) => Ok(Some(message)),
            Err(error) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        };

        // Use `advance` to modify the source such that it no longer contains this frame.
        source.advance(4 + length);

        message
    }
}