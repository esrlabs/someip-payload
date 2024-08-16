//! Contains the SOME/IP types.

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::any::Any;
use std::fmt::Display;
use thiserror::Error;
use ux::{i24, u24};

/// Trait for type serialization.
pub trait SOMType: Display {
    /// Serializes the type into the provided serializer.
    ///
    /// Returns the number of bytes being consumed from the serializer or an error.
    fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError>;

    /// Parses the type from the provided parser.
    ///
    /// Returns the number of bytes being consumed from the parser or an error.
    fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError>;

    /// Returns the size in bytes of the type if being serialization.
    fn size(&self) -> usize;

    /// Returns the category of the type.
    fn category(&self) -> SOMTypeCategory {
        SOMTypeCategory::FixedLength // default
    }

    /// Returns the type as an std::any::Any.
    fn as_any(&self) -> &dyn Any;
}

/// Trait for type metadata.
pub trait SOMTypeWithMeta {
    /// Adds metadata to an existing type.
    fn with_meta(self, meta: SOMTypeMeta) -> Self;

    /// Returns the metadata of the type.
    fn meta(&self) -> Option<&SOMTypeMeta>;
}

#[doc(hidden)]
const ERROR_TAG: &str = "SOME/IP Error";

/// Different kinds of errors.
#[derive(Error, Debug)]
pub enum SOMTypeError {
    /// Error for an unexpected end of buffer.
    #[error("{}: {0}", ERROR_TAG)]
    BufferExhausted(String),
    /// Error for an invalid payload.
    #[error("{}: {0}", ERROR_TAG)]
    InvalidPayload(String),
    /// Error for an invalid type.
    #[error("{}: {0}", ERROR_TAG)]
    InvalidType(String),
    /// Error for an invalid UTF-8 format.
    #[error("{}: {0:?}", ERROR_TAG)]
    Utf8Error(#[from] std::string::FromUtf8Error),
    /// Error for an invalid UTF-16 format.
    #[error("{}: {0:?}", ERROR_TAG)]
    Utf16Error(#[from] std::string::FromUtf16Error),
}

/// Different kinds of type categories.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SOMTypeCategory {
    /// Category of types with a fixed length.
    FixedLength,
    /// Category of types with an implicit length provided by a model.
    ImplicitLength,
    /// Category of types with an explicit length provided by a length-field.
    ExplicitLength,
}

/// Different kinds of endianness.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SOMEndian {
    /// Represents big endianness.
    Big,
    /// Represents little endianness.
    Little,
}

/// Different kinds of lengthfields.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SOMLengthField {
    /// Represents no lengthfield.
    None,
    /// Represents a u8 lengthfield.
    U8,
    /// Represents a u16 lengthfield.
    U16,
    /// Represents a u32 lengthfield.
    U32,
}

impl SOMLengthField {
    #[doc(hidden)]
    fn size(&self) -> usize {
        match self {
            SOMLengthField::None => 0usize,
            SOMLengthField::U8 => std::mem::size_of::<u8>(),
            SOMLengthField::U16 => std::mem::size_of::<u16>(),
            SOMLengthField::U32 => std::mem::size_of::<u32>(),
        }
    }
}

/// Different kinds of typefields.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SOMTypeField {
    /// Represents a u8 typefield.
    U8,
    /// Represents a u16 typefield.
    U16,
    /// Represents a u32 typefield.
    U32,
}

impl SOMTypeField {
    #[doc(hidden)]
    fn size(&self) -> usize {
        match self {
            SOMTypeField::U8 => std::mem::size_of::<u8>(),
            SOMTypeField::U16 => std::mem::size_of::<u16>(),
            SOMTypeField::U32 => std::mem::size_of::<u32>(),
        }
    }
}

/// Represents the metadata associated with a type.
#[derive(Debug, Clone)]
pub struct SOMTypeMeta {
    /// Represents a name associated with a type.
    pub name: String,
    /// Represents a description associated with a type.
    pub description: String,
}

impl SOMTypeMeta {
    /// Creates a new empty metadata.
    pub fn empty() -> Self {
        SOMTypeMeta {
            name: String::from(""),
            description: String::from(""),
        }
    }

    /// Creates a new metadata from the given name and description.
    pub fn from(name: String, description: String) -> Self {
        SOMTypeMeta { name, description }
    }

    /// Returns a string respresentation of the metadata.
    pub fn to_str(&self) -> String {
        if self.name.is_empty() || self.description.is_empty() {
            self.name.clone()
        } else {
            format!("{} ({})", self.name, self.description)
        }
    }
}

/// Serializer for SOME/IP types.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMBool::from(true);
/// let mut buffer = vec![0u8; obj.size()];
///
/// let mut serializer = SOMSerializer::new(&mut buffer[..]);
/// obj.serialize(&mut serializer)?;
/// # Ok::<(), SOMTypeError>(())
/// ```
pub struct SOMSerializer<'a> {
    #[doc(hidden)]
    buffer: &'a mut [u8],
    #[doc(hidden)]
    offset: usize,
}

#[doc(hidden)]
struct SOMSerializerPromise {
    offset: usize,
    size: usize,
}

impl<'a> SOMSerializer<'a> {
    /// Creates a new serializer for the given buffer.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        SOMSerializer { buffer, offset: 0 }
    }
}

#[doc(hidden)]
impl<'a> SOMSerializer<'a> {
    fn offset(&self) -> usize {
        self.offset
    }

    fn promise(&mut self, size: usize) -> Result<SOMSerializerPromise, SOMTypeError> {
        self.check_size(size)?;
        let result = SOMSerializerPromise {
            offset: self.offset,
            size,
        };
        self.offset += size;
        Ok(result)
    }

    fn write_lengthfield(
        &mut self,
        promise: SOMSerializerPromise,
        lengthfield: SOMLengthField,
        value: usize,
    ) -> Result<(), SOMTypeError> {
        if promise.size != lengthfield.size() {
            return Err(SOMTypeError::InvalidType(format!(
                "Invalid Length-Field size {} at offset {}",
                lengthfield.size(),
                promise.offset
            )));
        }

        match lengthfield {
            SOMLengthField::None => {}
            SOMLengthField::U8 => self.buffer[promise.offset] = value as u8,
            SOMLengthField::U16 => {
                BigEndian::write_u16(&mut self.buffer[promise.offset..], value as u16)
            }
            SOMLengthField::U32 => {
                BigEndian::write_u32(&mut self.buffer[promise.offset..], value as u32)
            }
        };

        Ok(())
    }

    fn write_typefield(
        &mut self,
        typefield: SOMTypeField,
        value: usize,
    ) -> Result<(), SOMTypeError> {
        match typefield {
            SOMTypeField::U8 => self.write_u8(value as u8)?,
            SOMTypeField::U16 => self.write_u16(value as u16, SOMEndian::Big)?,
            SOMTypeField::U32 => self.write_u32(value as u32, SOMEndian::Big)?,
        };

        Ok(())
    }

    fn write_bool(&mut self, value: bool) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<bool>();
        self.check_size(size)?;

        self.buffer[self.offset] = match value {
            true => 1,
            false => 0,
        };

        self.offset += size;
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<u8>();
        self.check_size(size)?;

        self.buffer[self.offset] = value;

        self.offset += size;
        Ok(())
    }

    fn write_i8(&mut self, value: i8) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<i8>();
        self.check_size(size)?;

        self.buffer[self.offset] = value as u8;

        self.offset += size;
        Ok(())
    }

    fn write_u16(&mut self, value: u16, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<u16>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => BigEndian::write_u16(&mut self.buffer[self.offset..], value),
            SOMEndian::Little => LittleEndian::write_u16(&mut self.buffer[self.offset..], value),
        }

        self.offset += size;
        Ok(())
    }

    fn write_i16(&mut self, value: i16, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<i16>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => BigEndian::write_i16(&mut self.buffer[self.offset..], value),
            SOMEndian::Little => LittleEndian::write_i16(&mut self.buffer[self.offset..], value),
        }

        self.offset += size;
        Ok(())
    }

    fn write_u24(&mut self, value: u24, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<u16>() + std::mem::size_of::<u8>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => {
                BigEndian::write_uint(&mut self.buffer[self.offset..], u64::from(value), size)
            }
            SOMEndian::Little => {
                LittleEndian::write_uint(&mut self.buffer[self.offset..], u64::from(value), size)
            }
        }

        self.offset += size;
        Ok(())
    }

    fn write_i24(&mut self, value: i24, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<i16>() + std::mem::size_of::<i8>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => {
                BigEndian::write_int(&mut self.buffer[self.offset..], i64::from(value), size)
            }
            SOMEndian::Little => {
                LittleEndian::write_int(&mut self.buffer[self.offset..], i64::from(value), size)
            }
        }

        self.offset += size;
        Ok(())
    }

    fn write_u32(&mut self, value: u32, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<u32>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => BigEndian::write_u32(&mut self.buffer[self.offset..], value),
            SOMEndian::Little => LittleEndian::write_u32(&mut self.buffer[self.offset..], value),
        }

        self.offset += size;
        Ok(())
    }

    fn write_i32(&mut self, value: i32, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<i32>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => BigEndian::write_i32(&mut self.buffer[self.offset..], value),
            SOMEndian::Little => LittleEndian::write_i32(&mut self.buffer[self.offset..], value),
        }

        self.offset += size;
        Ok(())
    }

    fn write_u64(&mut self, value: u64, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<u64>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => BigEndian::write_u64(&mut self.buffer[self.offset..], value),
            SOMEndian::Little => LittleEndian::write_u64(&mut self.buffer[self.offset..], value),
        }

        self.offset += size;
        Ok(())
    }

    fn write_i64(&mut self, value: i64, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<i64>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => BigEndian::write_i64(&mut self.buffer[self.offset..], value),
            SOMEndian::Little => LittleEndian::write_i64(&mut self.buffer[self.offset..], value),
        }

        self.offset += size;
        Ok(())
    }

    fn write_f32(&mut self, value: f32, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<f32>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => BigEndian::write_f32(&mut self.buffer[self.offset..], value),
            SOMEndian::Little => LittleEndian::write_f32(&mut self.buffer[self.offset..], value),
        }

        self.offset += size;
        Ok(())
    }

    fn write_f64(&mut self, value: f64, endian: SOMEndian) -> Result<(), SOMTypeError> {
        let size = std::mem::size_of::<f64>();
        self.check_size(size)?;

        match endian {
            SOMEndian::Big => BigEndian::write_f64(&mut self.buffer[self.offset..], value),
            SOMEndian::Little => LittleEndian::write_f64(&mut self.buffer[self.offset..], value),
        }

        self.offset += size;
        Ok(())
    }

    fn check_size(&self, size: usize) -> Result<(), SOMTypeError> {
        if self.buffer.len() < (self.offset + size) {
            return Err(SOMTypeError::BufferExhausted(format!(
                "Serializer exhausted at offset {} for Object size {}",
                self.offset, size
            )));
        }

        Ok(())
    }
}

/// Parser for SOME/IP types.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let buffer: [u8;1] = [0x01];
/// let mut parser = SOMParser::new(&buffer);
///
/// let mut obj = SOMu8::empty();
/// obj.parse(&mut parser)?;
/// # Ok::<(), SOMTypeError>(())
/// ```
pub struct SOMParser<'a> {
    #[doc(hidden)]
    buffer: &'a [u8],
    #[doc(hidden)]
    offset: usize,
}

impl<'a> SOMParser<'a> {
    /// Creates a new parser for the given buffer.
    pub fn new(buffer: &'a [u8]) -> Self {
        SOMParser { buffer, offset: 0 }
    }
}

#[doc(hidden)]
impl<'a> SOMParser<'a> {
    fn offset(&self) -> usize {
        self.offset
    }

    fn skip(&mut self, size: usize) -> Result<(), SOMTypeError> {
        self.check_size(size)?;
        self.offset += size;
        Ok(())
    }

    fn read_lengthfield(&mut self, lengthfield: SOMLengthField) -> Result<usize, SOMTypeError> {
        let size = lengthfield.size();
        self.check_size(size)?;

        let result = match lengthfield {
            SOMLengthField::None => 0usize,
            SOMLengthField::U8 => self.read_u8()? as usize,
            SOMLengthField::U16 => self.read_u16(SOMEndian::Big)? as usize,
            SOMLengthField::U32 => self.read_u32(SOMEndian::Big)? as usize,
        };

        Ok(result)
    }

    fn read_typefield(&mut self, typefield: &mut SOMTypeField) -> Result<usize, SOMTypeError> {
        let size = typefield.size();
        self.check_size(size)?;

        let result = match typefield {
            SOMTypeField::U8 => self.read_u8()? as usize,
            SOMTypeField::U16 => self.read_u16(SOMEndian::Big)? as usize,
            SOMTypeField::U32 => self.read_u32(SOMEndian::Big)? as usize,
        };

        Ok(result)
    }

    fn read_bool(&mut self) -> Result<bool, SOMTypeError> {
        let size = std::mem::size_of::<bool>();
        self.check_size(size)?;

        let value = self.buffer[self.offset];
        let result = match value {
            1 => true,
            0 => false,
            _ => {
                return Err(SOMTypeError::InvalidPayload(format!(
                    "Invalid Bool value {} at offset {}",
                    value, self.offset
                )))
            }
        };

        self.offset += size;
        Ok(result)
    }

    fn read_u8(&mut self) -> Result<u8, SOMTypeError> {
        let size = std::mem::size_of::<u8>();
        self.check_size(size)?;

        let result = self.buffer[self.offset];

        self.offset += size;
        Ok(result)
    }

    fn read_i8(&mut self) -> Result<i8, SOMTypeError> {
        let size = std::mem::size_of::<i8>();
        self.check_size(size)?;

        let result = self.buffer[self.offset] as i8;

        self.offset += size;
        Ok(result)
    }

    fn read_u16(&mut self, endian: SOMEndian) -> Result<u16, SOMTypeError> {
        let size = std::mem::size_of::<u16>();
        self.check_size(size)?;

        let result = match endian {
            SOMEndian::Big => BigEndian::read_u16(&self.buffer[self.offset..]),
            SOMEndian::Little => LittleEndian::read_u16(&self.buffer[self.offset..]),
        };

        self.offset += size;
        Ok(result)
    }

    fn read_i16(&mut self, endian: SOMEndian) -> Result<i16, SOMTypeError> {
        let size = std::mem::size_of::<i16>();
        self.check_size(size)?;

        let result = match endian {
            SOMEndian::Big => BigEndian::read_i16(&self.buffer[self.offset..]),
            SOMEndian::Little => LittleEndian::read_i16(&self.buffer[self.offset..]),
        };

        self.offset += size;
        Ok(result)
    }

    fn read_u24(&mut self, endian: SOMEndian) -> Result<u24, SOMTypeError> {
        let size = std::mem::size_of::<u16>() + std::mem::size_of::<u8>();
        self.check_size(size)?;

        let result = u24::new(match endian {
            SOMEndian::Big => BigEndian::read_uint(&self.buffer[self.offset..], size),
            SOMEndian::Little => LittleEndian::read_uint(&self.buffer[self.offset..], size),
        } as u32);

        self.offset += size;
        Ok(result)
    }

    fn read_i24(&mut self, endian: SOMEndian) -> Result<i24, SOMTypeError> {
        let size = std::mem::size_of::<i16>() + std::mem::size_of::<i8>();
        self.check_size(size)?;

        let result = i24::new(match endian {
            SOMEndian::Big => BigEndian::read_int(&self.buffer[self.offset..], size),
            SOMEndian::Little => LittleEndian::read_int(&self.buffer[self.offset..], size),
        } as i32);

        self.offset += size;
        Ok(result)
    }

    fn read_u32(&mut self, endian: SOMEndian) -> Result<u32, SOMTypeError> {
        let size = std::mem::size_of::<u32>();
        self.check_size(size)?;

        let result = match endian {
            SOMEndian::Big => BigEndian::read_u32(&self.buffer[self.offset..]),
            SOMEndian::Little => LittleEndian::read_u32(&self.buffer[self.offset..]),
        };

        self.offset += size;
        Ok(result)
    }

    fn read_i32(&mut self, endian: SOMEndian) -> Result<i32, SOMTypeError> {
        let size = std::mem::size_of::<i32>();
        self.check_size(size)?;

        let result = match endian {
            SOMEndian::Big => BigEndian::read_i32(&self.buffer[self.offset..]),
            SOMEndian::Little => LittleEndian::read_i32(&self.buffer[self.offset..]),
        };

        self.offset += size;
        Ok(result)
    }

    fn read_u64(&mut self, endian: SOMEndian) -> Result<u64, SOMTypeError> {
        let size = std::mem::size_of::<u64>();
        self.check_size(size)?;

        let result = match endian {
            SOMEndian::Big => BigEndian::read_u64(&self.buffer[self.offset..]),
            SOMEndian::Little => LittleEndian::read_u64(&self.buffer[self.offset..]),
        };

        self.offset += size;
        Ok(result)
    }

    fn read_i64(&mut self, endian: SOMEndian) -> Result<i64, SOMTypeError> {
        let size = std::mem::size_of::<i64>();
        self.check_size(size)?;

        let result = match endian {
            SOMEndian::Big => BigEndian::read_i64(&self.buffer[self.offset..]),
            SOMEndian::Little => LittleEndian::read_i64(&self.buffer[self.offset..]),
        };

        self.offset += size;
        Ok(result)
    }

    fn read_f32(&mut self, endian: SOMEndian) -> Result<f32, SOMTypeError> {
        let size = std::mem::size_of::<f32>();
        self.check_size(size)?;

        let result = match endian {
            SOMEndian::Big => BigEndian::read_f32(&self.buffer[self.offset..]),
            SOMEndian::Little => LittleEndian::read_f32(&self.buffer[self.offset..]),
        };

        self.offset += size;
        Ok(result)
    }

    fn read_f64(&mut self, endian: SOMEndian) -> Result<f64, SOMTypeError> {
        let size = std::mem::size_of::<f64>();
        self.check_size(size)?;

        let result = match endian {
            SOMEndian::Big => BigEndian::read_f64(&self.buffer[self.offset..]),
            SOMEndian::Little => LittleEndian::read_f64(&self.buffer[self.offset..]),
        };

        self.offset += size;
        Ok(result)
    }

    fn check_size(&self, size: usize) -> Result<(), SOMTypeError> {
        if self.buffer.len() < (self.offset + size) {
            return Err(SOMTypeError::BufferExhausted(format!(
                "Parser exhausted at offset {} for Object size {}",
                self.offset, size
            )));
        }

        Ok(())
    }
}

/// Contains the primitive types.
pub(crate) mod primitives {
    use super::*;

    /// A primitive type.
    #[derive(Debug, Clone)]
    pub struct SOMPrimitiveType<T> {
        /// Optional metadata of the type.
        meta: Option<SOMTypeMeta>,
        /// Optional value of the type.
        value: Option<T>,
    }

    impl<T: Copy + PartialEq> SOMPrimitiveType<T> {
        /// Creates a new empty type.
        pub fn empty() -> Self {
            SOMPrimitiveType {
                meta: None,
                value: None,
            }
        }

        /// Creates a new type from the given value.
        pub fn from(value: T) -> Self {
            SOMPrimitiveType {
                meta: None,
                value: Some(value),
            }
        }

        /// Sets the value of the type.
        pub fn set(&mut self, value: T) {
            self.value = Some(value);
        }

        /// Returns the value of the type.
        pub fn get(&self) -> Option<T> {
            self.value
        }
    }

    impl<T: Copy + PartialEq> SOMTypeWithMeta for SOMPrimitiveType<T> {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.meta = Some(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.meta.as_ref()
        }
    }

    /// A primitive type with endianness.
    #[derive(Debug, Clone)]
    pub struct SOMPrimitiveTypeWithEndian<T> {
        /// The contained primitive type.
        primitive: SOMPrimitiveType<T>,
        /// The endianness of the type.
        endian: SOMEndian,
    }

    impl<T: Copy + PartialEq> SOMPrimitiveTypeWithEndian<T> {
        /// Creates a new empty type.
        pub fn empty(endian: SOMEndian) -> Self {
            SOMPrimitiveTypeWithEndian {
                primitive: SOMPrimitiveType::empty(),
                endian,
            }
        }

        /// Creates a new type from the given value.
        pub fn from(endian: SOMEndian, value: T) -> Self {
            SOMPrimitiveTypeWithEndian {
                endian,
                primitive: SOMPrimitiveType::from(value),
            }
        }

        /// Sets the value of the type.
        pub fn set(&mut self, value: T) {
            self.primitive.set(value);
        }

        /// Returns the value of the type.
        pub fn get(&self) -> Option<T> {
            self.primitive.get()
        }

        /// Returns the contained primitive type.
        pub(crate) fn primitive(&self) -> &SOMPrimitiveType<T> {
            &self.primitive
        }
    }

    impl<T: Copy + PartialEq> SOMTypeWithMeta for SOMPrimitiveTypeWithEndian<T> {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.primitive = self.primitive.with_meta(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.primitive.meta()
        }
    }

    impl SOMType for SOMPrimitiveType<bool> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_bool(value)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_bool()?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<bool>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveType<u8> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_u8(value)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_u8()?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u8>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveType<i8> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_i8(value)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_i8()?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<i8>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<u16> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_u16(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_u16(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u16>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<i16> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_i16(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_i16(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<i16>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<u24> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_u24(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_u24(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u16>() + std::mem::size_of::<u8>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<i24> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_i24(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_i24(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<i16>() + std::mem::size_of::<i8>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<u32> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_u32(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_u32(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u32>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<i32> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_i32(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_i32(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<i32>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<u64> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_u64(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_u64(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u64>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<i64> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_i64(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_i64(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<i64>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<f32> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_f32(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_f32(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<f32>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMPrimitiveTypeWithEndian<f64> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            match self.get() {
                Some(value) => serializer.write_f64(value, self.endian)?,
                None => {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized Type at offset {}",
                        offset
                    )))
                }
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            self.set(parser.read_f64(self.endian)?);

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<f64>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }
}

/// Type for a bool.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMBool::from(true);
/// ```
pub type SOMBool = primitives::SOMPrimitiveType<bool>;

/// Type for a u8.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMu8::from(195u8);
/// ```
pub type SOMu8 = primitives::SOMPrimitiveType<u8>;

/// Type for a i8.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMi8::from(-95i8);
/// ```
pub type SOMi8 = primitives::SOMPrimitiveType<i8>;

/// Type for a u16.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMu16::from(SOMEndian::Big, 49200u16);
/// ```
pub type SOMu16 = primitives::SOMPrimitiveTypeWithEndian<u16>;

/// Type for a i16.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMi16::from(SOMEndian::Big, -9200i16);
/// ```
pub type SOMi16 = primitives::SOMPrimitiveTypeWithEndian<i16>;

/// Type for a u24.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// use ux::u24;
///
/// let obj = SOMu24::from(SOMEndian::Big, u24::new(12513060u32));
/// ```
pub type SOMu24 = primitives::SOMPrimitiveTypeWithEndian<u24>;
/// Type for a i24.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// use ux::i24;
///
/// let obj = SOMi24::from(SOMEndian::Big, i24::new(-2513060i32));
/// ```
pub type SOMi24 = primitives::SOMPrimitiveTypeWithEndian<i24>;

/// Type for a u32.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMu32::from(SOMEndian::Big, 3405691582u32);
/// ```
pub type SOMu32 = primitives::SOMPrimitiveTypeWithEndian<u32>;

/// Type for a i32.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMi32::from(SOMEndian::Big, -405691582i32);
/// ```
pub type SOMi32 = primitives::SOMPrimitiveTypeWithEndian<i32>;

/// Type for a u64.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMu64::from(SOMEndian::Big, 16045704242864831166u64);
/// ```
pub type SOMu64 = primitives::SOMPrimitiveTypeWithEndian<u64>;

/// Type for a i64.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMi64::from(SOMEndian::Big, -6045704242864831166i64);
/// ```
pub type SOMi64 = primitives::SOMPrimitiveTypeWithEndian<i64>;

/// Type for a f32.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMf32::from(SOMEndian::Big, 1.0f32);
/// ```
pub type SOMf32 = primitives::SOMPrimitiveTypeWithEndian<f32>;

/// Type for a f64.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMf64::from(SOMEndian::Big, 1.0f64);
/// ```
pub type SOMf64 = primitives::SOMPrimitiveTypeWithEndian<f64>;

/// Contains the array types.
pub(crate) mod arrays {
    use super::*;

    /// An array type.
    ///
    /// An array is either of fixed or dynamic length.
    #[derive(Debug, Clone)]
    pub struct SOMArrayType<T: SOMType + Any + Clone> {
        /// Optional metadata of the type.
        meta: Option<SOMTypeMeta>,
        /// The lengthfield of the type.
        lengthfield: SOMLengthField,
        /// The elements of the type.
        elements: Vec<T>,
        /// Current number of elements.
        length: usize,
        /// Minimum number of elements necessary.
        min: usize,
        /// Maximum number of elements allowed.
        max: usize,
    }

    impl<T: SOMType + Any + Clone> SOMArrayType<T> {
        /// Creates a new array from the given elements.
        pub fn from(lengthfield: SOMLengthField, min: usize, max: usize, elements: Vec<T>) -> Self {
            let size: usize = elements.len();
            SOMArrayType {
                meta: None,
                lengthfield,
                elements,
                length: size,
                min,
                max,
            }
        }

        /// Creates a new empty array of fixed length.
        pub fn fixed(element: T, size: usize) -> Self {
            SOMArrayType {
                meta: None,
                lengthfield: SOMLengthField::None,
                elements: vec![element; size],
                length: 0usize,
                min: size,
                max: size,
            }
        }

        /// Creates a new empty array of dynamic length.
        pub fn dynamic(lengthfield: SOMLengthField, element: T, min: usize, max: usize) -> Self {
            SOMArrayType {
                meta: None,
                lengthfield,
                elements: vec![element; max],
                length: 0usize,
                min,
                max,
            }
        }

        /// Returns whether this array is dynamic.
        pub fn is_dynamic(&self) -> bool {
            self.min != self.max
        }

        /// Returns the maximum number of elements allowed.
        pub fn max(&self) -> usize {
            self.max
        }

        /// Returns the minimum number of elements necessary.
        pub fn min(&self) -> usize {
            self.min
        }

        /// Returns the current number of elements.
        pub fn len(&self) -> usize {
            self.length
        }

        /// Returns the element at given index, if any.
        ///
        /// Note: The index of the element shall be zero-based.
        pub fn get(&self, index: usize) -> Option<&T> {
            if index < self.length {
                return self.elements.get(index);
            }

            None
        }

        /// Returns the mutable element at given index and
        /// adjusts the current number of elements if necessary.
        ///
        /// Note: The index of the element shall be zero-based.
        pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
            if self.apply_len(index) {
                return self.elements.get_mut(index);
            }

            None
        }

        /// Clears the current number of elements.
        pub fn clear(&mut self) {
            self.length = 0;
        }

        #[doc(hidden)]
        fn apply_len(&mut self, index: usize) -> bool {
            if index < self.max {
                if index + 1usize > self.len() {
                    self.length = index + 1usize;
                }
                return true;
            }

            false
        }

        #[doc(hidden)]
        fn validate(&self, offset: usize) -> Result<(), SOMTypeError> {
            let length: usize = self.len();

            if (length < self.min) || (length > self.max) {
                return Err(SOMTypeError::InvalidType(format!(
                    "Invalid Array length {} at offset {}",
                    length, offset
                )));
            }

            Ok(())
        }
    }

    impl<T: SOMType + Any + Clone> SOMType for SOMArrayType<T> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();
            self.validate(offset)?;

            let type_lengthfield = serializer.promise(self.lengthfield.size())?;

            for i in 0..self.len() {
                if let Some(element) = self.get(i) {
                    element.serialize(serializer)?;
                }
            }

            let size = serializer.offset() - offset;
            if self.is_dynamic() {
                serializer.write_lengthfield(
                    type_lengthfield,
                    self.lengthfield,
                    size - self.lengthfield.size(),
                )?;
            }

            Ok(size)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            let type_lengthfield = parser.read_lengthfield(self.lengthfield)?;

            self.clear();
            if self.is_dynamic() {
                let type_start = parser.offset();

                while (parser.offset() - type_start) < type_lengthfield {
                    if let Some(element) = self.get_mut(self.len()) {
                        element.parse(parser)?;
                    } else {
                        return Err(SOMTypeError::InvalidPayload(format!(
                            "Missing Array-Element at offset {}",
                            offset
                        )));
                    }
                }
            } else {
                for _ in 0..self.max {
                    if let Some(element) = self.get_mut(self.len()) {
                        element.parse(parser)?;
                    } else {
                        return Err(SOMTypeError::InvalidPayload(format!(
                            "Missing Array-Element at offset {}",
                            offset
                        )));
                    }
                }
            }

            let size = parser.offset() - offset;
            if self.is_dynamic() && (type_lengthfield != (size - self.lengthfield.size())) {
                return Err(SOMTypeError::InvalidPayload(format!(
                    "Invalid Length-Field value {} at offset {}",
                    type_lengthfield, offset
                )));
            }

            self.validate(offset)?;
            Ok(size)
        }

        fn size(&self) -> usize {
            let mut size: usize = 0;

            size += self.lengthfield.size();
            for i in 0..self.len() {
                if let Some(element) = self.get(i) {
                    size += element.size();
                }
            }

            size
        }

        fn category(&self) -> SOMTypeCategory {
            if self.is_dynamic() {
                SOMTypeCategory::ExplicitLength
            } else {
                SOMTypeCategory::ImplicitLength
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl<T: SOMType + Any + Clone> SOMTypeWithMeta for SOMArrayType<T> {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.meta = Some(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.meta.as_ref()
        }
    }
}

/// Type for a complex array member.
///
/// See also [SOMArray]
pub type SOMArrayMember = wrapper::SOMTypeWrapper;

/// Type for a complex array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMArray::fixed(
///     SOMArrayMember::Struct(SOMStruct::from(vec![
///         SOMStructMember::Bool(SOMBool::empty()),
///         SOMStructMember::U16(SOMu16::empty(SOMEndian::Big)),
///     ])),
///     3, // max
/// );
///
/// let obj2 = SOMArray::dynamic(
///     SOMLengthField::U32,
///     SOMArrayMember::Struct(SOMStruct::from(vec![
///         SOMStructMember::Bool(SOMBool::empty()),
///         SOMStructMember::U16(SOMu16::empty(SOMEndian::Big)),
///     ])),
///     0, // min
///     3, // max
/// );
/// ```
pub type SOMArray = arrays::SOMArrayType<SOMArrayMember>;

/// Type for a bool array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMBoolArray::fixed(SOMBool::empty(), 3);
///
/// let obj2 = SOMBoolArray::dynamic(SOMLengthField::U32, SOMBool::empty(), 0, 3);
/// ```
pub type SOMBoolArray = arrays::SOMArrayType<SOMBool>;

/// Type for a u8 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMu8Array::fixed(SOMu8::empty(), 3);
///
/// let obj2 = SOMu8Array::dynamic(SOMLengthField::U32, SOMu8::empty(), 0, 3);
/// ```
pub type SOMu8Array = arrays::SOMArrayType<SOMu8>;

/// Type for a i8 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMi8Array::fixed(SOMi8::empty(), 3);
///
/// let obj2 = SOMi8Array::dynamic(SOMLengthField::U32, SOMi8::empty(), 0, 3);
/// ```
pub type SOMi8Array = arrays::SOMArrayType<SOMi8>;

/// Type for a u16 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMu16Array::fixed(SOMu16::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMu16Array::dynamic(SOMLengthField::U32, SOMu16::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMu16Array = arrays::SOMArrayType<SOMu16>;

/// Type for a i16 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMi16Array::fixed(SOMi16::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMi16Array::dynamic(SOMLengthField::U32, SOMi16::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMi16Array = arrays::SOMArrayType<SOMi16>;

/// Type for a u24 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// use ux::u24;
///
/// let obj1 = SOMu24Array::fixed(SOMu24::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMu24Array::dynamic(SOMLengthField::U32, SOMu24::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMu24Array = arrays::SOMArrayType<SOMu24>;

/// Type for a i24 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// use ux::i24;
///
/// let obj1 = SOMi24Array::fixed(SOMi24::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMi24Array::dynamic(SOMLengthField::U32, SOMi24::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMi24Array = arrays::SOMArrayType<SOMi24>;

/// Type for a u32 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMu32Array::fixed(SOMu32::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMu32Array::dynamic(SOMLengthField::U32, SOMu32::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMu32Array = arrays::SOMArrayType<SOMu32>;

/// Type for a i32 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMi32Array::fixed(SOMi32::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMi32Array::dynamic(SOMLengthField::U32, SOMi32::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMi32Array = arrays::SOMArrayType<SOMi32>;

/// Type for a u64 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMu64Array::fixed(SOMu64::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMu64Array::dynamic(SOMLengthField::U32, SOMu64::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMu64Array = arrays::SOMArrayType<SOMu64>;

/// Type for a i64 array.
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMi64Array::fixed(SOMi64::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMi64Array::dynamic(SOMLengthField::U32, SOMi64::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMi64Array = arrays::SOMArrayType<SOMi64>;

/// Type for a f32 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMf32Array::fixed(SOMf32::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMf32Array::dynamic(SOMLengthField::U32, SOMf32::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMf32Array = arrays::SOMArrayType<SOMf32>;

/// Type for a f64 array.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj1 = SOMf64Array::fixed(SOMf64::empty(SOMEndian::Big), 3);
///
/// let obj2 = SOMf64Array::dynamic(SOMLengthField::U32, SOMf64::empty(SOMEndian::Big), 0, 3);
/// ```
pub type SOMf64Array = arrays::SOMArrayType<SOMf64>;

/// Contains the struct types.
pub(crate) mod structs {
    use super::*;

    /// A struct type.
    #[derive(Debug, Clone)]
    pub struct SOMStructType<T: SOMType> {
        /// Optional metadata of the type.
        meta: Option<SOMTypeMeta>,
        /// The members of the type.
        members: Vec<T>,
    }

    impl<T: SOMType> SOMStructType<T> {
        /// Creates a new struct from the given members.
        pub fn from(members: Vec<T>) -> Self {
            SOMStructType {
                meta: None,
                members,
            }
        }

        /// Returns the number of members.
        pub fn len(&self) -> usize {
            self.members.len()
        }

        /// Returns the members at given index, if any.
        ///
        /// Note: The index of the member shall be zero-based.
        pub fn get(&self, index: usize) -> Option<&T> {
            self.members.get(index)
        }

        /// Returns the mutable members at given index, if any.
        ///
        /// Note: The index of the member shall be zero-based.
        pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
            self.members.get_mut(index)
        }
    }

    impl<T: SOMType + Any> SOMType for SOMStructType<T> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            for member in &self.members {
                member.serialize(serializer)?;
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            for member in &mut self.members {
                member.parse(parser)?;
            }

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            let mut size: usize = 0;

            for member in &self.members {
                size += member.size();
            }

            size
        }

        fn category(&self) -> SOMTypeCategory {
            SOMTypeCategory::ImplicitLength
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl<T: SOMType> SOMTypeWithMeta for SOMStructType<T> {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.meta = Some(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.meta.as_ref()
        }
    }
}

/// Type for a struct member.
///
/// See also [SOMStruct]
pub type SOMStructMember = wrapper::SOMTypeWrapper;

/// Type for a struct.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let obj = SOMStruct::from(vec![
///     SOMStructMember::Bool(SOMBool::from(true)),
///     SOMStructMember::U16(SOMu16::from(SOMEndian::Big, 49200u16)),
/// ]);
/// ```
pub type SOMStruct = structs::SOMStructType<SOMStructMember>;

/// Contains the union types.
pub(crate) mod unions {
    use super::*;

    #[doc(hidden)]
    const INVALID_TYPE: usize = 0usize;

    /// An union type.
    ///
    /// An union can have one of its members being selected to store its value.
    #[derive(Debug, Clone)]
    pub struct SOMUnionType<T: SOMType + Any> {
        /// Optional metadata of the type.
        meta: Option<SOMTypeMeta>,
        /// The typefield of the type
        typefield: SOMTypeField,
        /// The members of the type.
        members: Vec<T>,
        /// The index of the currently selected member.
        index: usize,
    }

    impl<T: SOMType + Any> SOMUnionType<T> {
        /// Creates a new union from the given members.
        pub fn from(typefield: SOMTypeField, members: Vec<T>) -> Self {
            SOMUnionType {
                meta: None,
                typefield,
                members,
                index: INVALID_TYPE,
            }
        }

        /// Returns the number of members.
        pub fn len(&self) -> usize {
            self.members.len()
        }

        /// Returns if currently a member is being selected.
        pub fn has_value(&self) -> bool {
            self.index != INVALID_TYPE
        }

        /// Selects the member at given index and returns true if successfully.
        ///
        /// Note: The index of the member shall be one-based.
        pub fn set(&mut self, index: usize) -> bool {
            if index != INVALID_TYPE && index <= self.len() {
                self.index = index;
                return true;
            }

            false
        }

        /// Returns the currently selected member, if any.
        pub fn get(&self) -> Option<&T> {
            if self.has_value() {
                self.members.get(self.index - 1)
            } else {
                None
            }
        }

        /// Selects and returns the mutable member at given index, if any.
        ///
        /// Note: The index of the member shall be one-based.
        pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
            if self.set(index) {
                self.members.get_mut(index - 1)
            } else {
                None
            }
        }

        /// Clears the currently selected member.
        pub fn clear(&mut self) {
            self.index = INVALID_TYPE;
        }
    }

    impl<T: SOMType + Any> SOMType for SOMUnionType<T> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            serializer.write_typefield(self.typefield, self.index)?;

            if let Some(value) = self.get() {
                value.serialize(serializer)?;
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            let index = parser.read_typefield(&mut self.typefield)?;

            if index <= self.len() {
                self.index = index;
            } else {
                return Err(SOMTypeError::InvalidPayload(format!(
                    "Invalid Union index {} at offset {}",
                    index, offset
                )));
            }

            if let Some(value) = self.get_mut(index) {
                value.parse(parser)?;
            }

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            let mut size: usize = 0;

            size += self.typefield.size();
            if let Some(value) = self.get() {
                size += value.size();
            }

            size
        }

        fn category(&self) -> SOMTypeCategory {
            SOMTypeCategory::ImplicitLength
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl<T: SOMType + Any> SOMTypeWithMeta for SOMUnionType<T> {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.meta = Some(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.meta.as_ref()
        }
    }
}

/// Type for an union member.
///
/// See also [SOMUnion]
pub type SOMUnionMember = wrapper::SOMTypeWrapper;

/// Type for an union.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let mut obj = SOMUnion::from(
///     SOMTypeField::U8,
///     vec![
///         SOMUnionMember::Bool(SOMBool::from(true)),
///         SOMUnionMember::U16(SOMu16::from(SOMEndian::Big, 49200u16)),
///     ],
/// );
///
/// obj.set(1); // SOMUnionMember::Bool
/// ```
pub type SOMUnion = unions::SOMUnionType<SOMUnionMember>;

/// Contains the enum types.
pub(crate) mod enums {
    use super::*;

    /// An enum item type.
    #[derive(Debug, Clone)]
    pub struct SOMEnumTypeItem<T> {
        /// The key of the item.
        key: String,
        /// The value of the item.
        value: T,
    }

    impl<T> SOMEnumTypeItem<T> {
        /// Creates a new item from the given key and value.
        pub fn from(key: String, value: T) -> Self {
            SOMEnumTypeItem { key, value }
        }

        /// Returns a tuple of the item's key and value.
        pub(crate) fn get(&self) -> (&str, &T) {
            (&self.key, &self.value)
        }
    }

    /// An enum type.
    ///
    /// An enum can have one of its elements being selected to represent its value.
    #[derive(Debug, Clone)]
    pub struct SOMEnumType<T> {
        /// Optional metadata of the type.
        meta: Option<SOMTypeMeta>,
        /// The elements of the type.
        elements: Vec<SOMEnumTypeItem<T>>,
        /// The index of the currently selected member.
        index: usize,
    }

    impl<T: Copy + PartialEq> SOMEnumType<T> {
        /// Creates a new enum from the given elements.
        pub fn from(elements: Vec<SOMEnumTypeItem<T>>) -> Self {
            SOMEnumType {
                meta: None,
                elements,
                index: 0,
            }
        }

        /// Returns the number of elements.
        pub fn len(&self) -> usize {
            self.elements.len()
        }

        /// Returns if currently an element is being selected.
        pub fn has_value(&self) -> bool {
            self.index != 0
        }

        /// Returns the currently selected element's value, if any.
        pub fn get_value(&self) -> Option<T> {
            if let Some(element) = self.get() {
                return Some(element.value);
            }

            None
        }

        /// Selects the element with the given key and returns true if successfully.
        pub fn set(&mut self, key: String) -> bool {
            let mut index: usize = 0;
            for element in &self.elements {
                index += 1;
                if element.key == key {
                    self.index = index;
                    return true;
                }
            }

            false
        }

        /// Returns the currently selected element, if any.
        pub(crate) fn get(&self) -> Option<&SOMEnumTypeItem<T>> {
            if self.has_value() {
                self.elements.get(self.index - 1)
            } else {
                None
            }
        }

        /// Clears the currently selected element.
        pub fn clear(&mut self) {
            self.index = 0;
        }

        #[doc(hidden)]
        fn apply(&mut self, value: T) -> bool {
            let mut index: usize = 0;
            for element in &self.elements {
                index += 1;
                if element.value == value {
                    self.index = index;
                    return true;
                }
            }

            false
        }
    }

    impl<T: Copy + PartialEq> SOMTypeWithMeta for SOMEnumType<T> {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.meta = Some(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.meta.as_ref()
        }
    }

    /// An enum type with endianness.
    ///
    /// An enum can have one of its elements being selected to represent its value.
    #[derive(Debug, Clone)]
    pub struct SOMEnumTypeWithEndian<T> {
        /// The contained enum type.
        enumeration: SOMEnumType<T>,
        /// The endianness of the type.
        endian: SOMEndian,
    }

    impl<T: Copy + PartialEq> SOMEnumTypeWithEndian<T> {
        /// Creates a new enum from the given elements.
        pub fn from(endian: SOMEndian, elements: Vec<SOMEnumTypeItem<T>>) -> Self {
            SOMEnumTypeWithEndian {
                enumeration: SOMEnumType::from(elements),
                endian,
            }
        }

        /// Returns the number of elements.
        pub fn len(&self) -> usize {
            self.enumeration.len()
        }

        /// Returns if currently an element is being selected.
        pub fn has_value(&self) -> bool {
            self.enumeration.has_value()
        }

        /// Returns the currently selected element's value, if any.
        pub fn get_value(&self) -> Option<T> {
            self.enumeration.get_value()
        }

        /// Selects the element with the given key and returns true if successfully.
        pub fn set(&mut self, key: String) -> bool {
            self.enumeration.set(key)
        }

        /// Clears the currently selected element.
        pub fn clear(&mut self) {
            self.enumeration.clear()
        }

        /// Returns the contained enum type.
        pub(crate) fn enumeration(&self) -> &SOMEnumType<T> {
            &self.enumeration
        }
    }

    impl<T: Copy + PartialEq> SOMTypeWithMeta for SOMEnumTypeWithEndian<T> {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.enumeration = self.enumeration.with_meta(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.enumeration.meta()
        }
    }

    impl SOMType for SOMEnumType<u8> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            if self.has_value() {
                if let Some(value) = self.get_value() {
                    let mut temp = SOMu8::empty();
                    temp.set(value);
                    temp.serialize(serializer)?;
                }
            } else {
                return Err(SOMTypeError::InvalidType(format!(
                    "Uninitialized Type at offset {}",
                    offset
                )));
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            let mut temp = SOMu8::empty();
            temp.parse(parser)?;

            if let Some(value) = temp.get() {
                if !self.apply(value) {
                    return Err(SOMTypeError::InvalidPayload(format!(
                        "Invalid Enum value {} at offset {}",
                        value, offset
                    )));
                }
            } else {
                return Err(SOMTypeError::InvalidType(format!(
                    "Uninitialized Type at offset {}",
                    offset
                )));
            }

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u8>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMEnumTypeWithEndian<u16> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            if self.has_value() {
                if let Some(value) = self.get_value() {
                    let mut temp = SOMu16::empty(self.endian);
                    temp.set(value);
                    temp.serialize(serializer)?;
                }
            } else {
                return Err(SOMTypeError::InvalidType(format!(
                    "Uninitialized Type at offset {}",
                    offset
                )));
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            let mut temp = SOMu16::empty(self.endian);
            temp.parse(parser)?;

            if let Some(value) = temp.get() {
                if !self.enumeration.apply(value) {
                    return Err(SOMTypeError::InvalidPayload(format!(
                        "Invalid Enum value {} at offset {}",
                        value, offset
                    )));
                }
            } else {
                return Err(SOMTypeError::InvalidType(format!(
                    "Uninitialized Type at offset {}",
                    offset
                )));
            }

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u16>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMEnumTypeWithEndian<u32> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            if self.has_value() {
                if let Some(value) = self.get_value() {
                    let mut temp = SOMu32::empty(self.endian);
                    temp.set(value);
                    temp.serialize(serializer)?;
                }
            } else {
                return Err(SOMTypeError::InvalidType(format!(
                    "Uninitialized Type at offset {}",
                    offset
                )));
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            let mut temp = SOMu32::empty(self.endian);
            temp.parse(parser)?;

            if let Some(value) = temp.get() {
                if !self.enumeration.apply(value) {
                    return Err(SOMTypeError::InvalidPayload(format!(
                        "Invalid Enum value {} at offset {}",
                        value, offset
                    )));
                }
            } else {
                return Err(SOMTypeError::InvalidType(format!(
                    "Uninitialized Type at offset {}",
                    offset
                )));
            }

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u32>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMType for SOMEnumTypeWithEndian<u64> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            if self.has_value() {
                if let Some(value) = self.get_value() {
                    let mut temp = SOMu64::empty(self.endian);
                    temp.set(value);
                    temp.serialize(serializer)?;
                }
            } else {
                return Err(SOMTypeError::InvalidType(format!(
                    "Uninitialized Type at offset {}",
                    offset
                )));
            }

            Ok(serializer.offset() - offset)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            let mut temp = SOMu64::empty(self.endian);
            temp.parse(parser)?;

            if let Some(value) = temp.get() {
                if !self.enumeration.apply(value) {
                    return Err(SOMTypeError::InvalidPayload(format!(
                        "Invalid Enum value {} at offset {}",
                        value, offset
                    )));
                }
            } else {
                return Err(SOMTypeError::InvalidType(format!(
                    "Uninitialized Type at offset {}",
                    offset
                )));
            }

            Ok(parser.offset() - offset)
        }

        fn size(&self) -> usize {
            std::mem::size_of::<u64>()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }
}

/// Type for a u8 enum item.
///
/// See also [SOMu8Enum]
pub type SOMu8EnumItem = enums::SOMEnumTypeItem<u8>;

/// Type for a u8 enum.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let mut obj = SOMu8Enum::from(vec![
///     SOMu8EnumItem::from(String::from("A"), 0u8),
///     SOMu8EnumItem::from(String::from("B"), 1u8),
/// ]);
///
/// obj.set(String::from("A"));
/// ```
pub type SOMu8Enum = enums::SOMEnumType<u8>;

/// Type for a u16 enum item.
///
/// See also [SOMu16Enum]
pub type SOMu16EnumItem = enums::SOMEnumTypeItem<u16>;

/// Type for a u16 enum.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let mut obj = SOMu16Enum::from(
///     SOMEndian::Big,
///     vec![
///         SOMu16EnumItem::from(String::from("A"), 49200u16),
///         SOMu16EnumItem::from(String::from("B"), 49201u16),
///     ]
/// );
///
/// obj.set(String::from("A"));
/// ```
pub type SOMu16Enum = enums::SOMEnumTypeWithEndian<u16>;

/// Type for a u32 enum item.
///
/// See also [SOMu32Enum]
pub type SOMu32EnumItem = enums::SOMEnumTypeItem<u32>;

/// Type for a u32 enum.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let mut obj = SOMu32Enum::from(
///     SOMEndian::Big,
///     vec![
///         SOMu32EnumItem::from(String::from("A"), 3405691580u32),
///         SOMu32EnumItem::from(String::from("B"), 3405691581u32),
///     ]
/// );
///
/// obj.set(String::from("A"));
/// ```
pub type SOMu32Enum = enums::SOMEnumTypeWithEndian<u32>;

/// Type for a u64 enum item.
///
/// See also [SOMu64Enum]
pub type SOMu64EnumItem = enums::SOMEnumTypeItem<u64>;

/// Type for a u64 enum.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let mut obj = SOMu64Enum::from(
///     SOMEndian::Big,
///     vec![
///         SOMu64EnumItem::from(String::from("A"), 16045704242864831160u64),
///         SOMu64EnumItem::from(String::from("B"), 16045704242864831161u64),
///     ]
/// );
///
/// obj.set(String::from("A"));
/// ```
pub type SOMu64Enum = enums::SOMEnumTypeWithEndian<u64>;

/// Contains the string types.
pub(crate) mod strings {
    use super::*;

    #[doc(hidden)]
    const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
    #[doc(hidden)]
    const UTF8_TERMINATION: [u8; 1] = [0x00];
    #[doc(hidden)]
    const UTF16_BOM_BE: [u8; 2] = [0xFE, 0xFF];
    #[doc(hidden)]
    const UTF16_BOM_LE: [u8; 2] = [0xFF, 0xFE];
    #[doc(hidden)]
    const UTF16_TERMINATION: [u8; 2] = [0x00, 0x00];

    /// Different kinds of string encodings.
    #[derive(Debug, Copy, Clone, PartialEq)]
    pub enum SOMStringEncoding {
        /// UTF-8 encoding
        Utf8,
        /// UTF-16 big-endian encoding
        Utf16Be,
        /// UTF-16 little-endian encoding
        Utf16Le,
    }

    /// Different kinds of string formats.
    #[derive(Debug, Copy, Clone, PartialEq)]
    pub enum SOMStringFormat {
        /// Plain string format.
        Plain,
        /// String format with leading BOM.
        WithBOM,
        /// String format with termination.
        WithTermination,
        /// String format with leading BOM and termination
        WithBOMandTermination,
    }

    #[doc(hidden)]
    fn char_size(encoding: SOMStringEncoding) -> usize {
        match encoding {
            SOMStringEncoding::Utf8 => std::mem::size_of::<u8>(),
            _ => std::mem::size_of::<u16>(),
        }
    }

    #[doc(hidden)]
    fn char_len(encoding: SOMStringEncoding, bytes: &[u8]) -> usize {
        let bytes_len = bytes.len();
        let char_size = char_size(encoding);

        let char_len = bytes_len / char_size;
        if (bytes_len % char_size) != 0 {
            return char_len + 1;
        }

        char_len
    }

    #[doc(hidden)]
    fn bom(encoding: SOMStringEncoding) -> Vec<u8> {
        match encoding {
            SOMStringEncoding::Utf8 => UTF8_BOM.to_vec(),
            SOMStringEncoding::Utf16Be => UTF16_BOM_BE.to_vec(),
            SOMStringEncoding::Utf16Le => UTF16_BOM_LE.to_vec(),
        }
    }

    #[doc(hidden)]
    fn termination(encoding: SOMStringEncoding) -> Vec<u8> {
        match encoding {
            SOMStringEncoding::Utf8 => UTF8_TERMINATION.to_vec(),
            _ => UTF16_TERMINATION.to_vec(),
        }
    }

    #[doc(hidden)]
    fn string_len(encoding: SOMStringEncoding, format: SOMStringFormat, value: &str) -> usize {
        let bom_len = char_len(encoding, &bom(encoding));
        let termination_len = char_len(encoding, &termination(encoding));

        value.len()
            + match format {
                SOMStringFormat::Plain => 0,
                SOMStringFormat::WithBOM => bom_len,
                SOMStringFormat::WithTermination => termination_len,
                SOMStringFormat::WithBOMandTermination => bom_len + termination_len,
            }
    }

    /// A string type.
    ///
    /// A string is either of fixed or dynamic length and
    /// consists of its value and an optional BOM and termination.
    #[derive(Debug, Clone)]
    pub struct SOMStringType {
        /// Optional metadata of the type.
        meta: Option<SOMTypeMeta>,
        /// The lengthfield of the type.
        lengthfield: SOMLengthField,
        /// The encoding of the type.
        encoding: SOMStringEncoding,
        /// The format of the type.
        format: SOMStringFormat,
        /// The value of the type.
        value: String,
        /// Minimum number of chars necessary.
        min: usize,
        /// Maximum number of chars allowed.
        max: usize,
    }

    impl SOMStringType {
        /// Creates a new array from the given value.
        pub fn from(
            lengthfield: SOMLengthField,
            encoding: SOMStringEncoding,
            format: SOMStringFormat,
            min: usize,
            max: usize,
            value: String,
        ) -> Self {
            SOMStringType {
                meta: None,
                lengthfield,
                encoding,
                format,
                value,
                min,
                max,
            }
        }

        /// Creates a new empty string of fixed length.
        pub fn fixed(encoding: SOMStringEncoding, format: SOMStringFormat, max: usize) -> Self {
            SOMStringType {
                meta: None,
                lengthfield: SOMLengthField::None,
                encoding,
                format,
                value: String::from(""),
                min: max,
                max,
            }
        }

        /// Creates a new empty string of dynamic length.
        pub fn dynamic(
            lengthfield: SOMLengthField,
            encoding: SOMStringEncoding,
            format: SOMStringFormat,
            min: usize,
            max: usize,
        ) -> Self {
            SOMStringType {
                meta: None,
                lengthfield,
                encoding,
                format,
                value: String::from(""),
                min,
                max,
            }
        }

        /// Returns whether this string is dynamic.
        pub fn is_dynamic(&self) -> bool {
            (self.min != self.max) || (self.lengthfield != SOMLengthField::None)
        }

        /// Returns the current number of chars,
        /// including any optional BOM and termination.
        pub fn len(&self) -> usize {
            string_len(self.encoding, self.format, &self.value)
        }

        /// Returns whether this string has a BOM.
        pub fn has_bom(&self) -> bool {
            matches!(
                self.format,
                SOMStringFormat::WithBOM | SOMStringFormat::WithBOMandTermination
            )
        }

        /// Returns whether this string has a termination.
        pub fn has_termination(&self) -> bool {
            matches!(
                self.format,
                SOMStringFormat::WithTermination | SOMStringFormat::WithBOMandTermination
            )
        }

        /// Sets the value of this string and returns true if successfully.
        ///
        /// Note: The given value shall be without any optional BOM and termination.
        pub fn set(&mut self, value: String) -> bool {
            if string_len(self.encoding, self.format, &value) <= self.max {
                self.value = value;
                return true;
            }

            false
        }

        /// Resturns the value of this string.
        ///
        /// Note: The given value will be without any optional BOM and termination.
        pub fn get(&self) -> &str {
            &self.value
        }

        /// Clears the value of this string.
        pub fn clear(&mut self) {
            self.value = String::from("");
        }

        #[doc(hidden)]
        fn endian(&self) -> SOMEndian {
            match self.encoding {
                SOMStringEncoding::Utf8 => SOMEndian::Big,
                SOMStringEncoding::Utf16Be => SOMEndian::Big,
                SOMStringEncoding::Utf16Le => SOMEndian::Little,
            }
        }

        #[doc(hidden)]
        fn bom(&self) -> Vec<u8> {
            match self.encoding {
                SOMStringEncoding::Utf8 => UTF8_BOM.to_vec(),
                SOMStringEncoding::Utf16Be => UTF16_BOM_BE.to_vec(),
                SOMStringEncoding::Utf16Le => UTF16_BOM_LE.to_vec(),
            }
        }

        #[doc(hidden)]
        fn termination(&self) -> Vec<u8> {
            match self.encoding {
                SOMStringEncoding::Utf8 => UTF8_TERMINATION.to_vec(),
                _ => UTF16_TERMINATION.to_vec(),
            }
        }

        #[doc(hidden)]
        fn validate(&self, offset: usize) -> Result<(), SOMTypeError> {
            let length: usize = self.len();

            let valid: bool = if self.is_dynamic() {
                (self.min <= length) && (length <= self.max)
            } else {
                length <= self.max
            };

            if !valid {
                return Err(SOMTypeError::InvalidType(format!(
                    "Invalid String length {} at offset {}",
                    length, offset
                )));
            }

            Ok(())
        }
    }

    impl SOMType for SOMStringType {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();
            self.validate(offset)?;

            let type_lengthfield = serializer.promise(self.lengthfield.size())?;

            let char_size = char_size(self.encoding);
            let mut string_size = 0usize;

            if self.has_bom() {
                for item in self.bom() {
                    serializer.write_u8(item)?;
                }
                string_size += char_size * char_len(self.encoding, &self.bom());
            }

            match self.encoding {
                SOMStringEncoding::Utf8 => {
                    let bytes: Vec<u8> = self.value.clone().into_bytes();
                    for item in bytes {
                        serializer.write_u8(item)?;
                        string_size += char_size;
                    }
                }
                _ => {
                    let bytes: Vec<u16> = self.value.encode_utf16().collect();
                    for item in bytes {
                        serializer.write_u16(item, self.endian())?;
                        string_size += char_size;
                    }
                }
            }

            if self.has_termination() {
                for item in self.termination() {
                    serializer.write_u8(item)?;
                }
                string_size += char_size * char_len(self.encoding, &self.termination());
            }

            let size;
            if self.is_dynamic() {
                size = serializer.offset() - offset;
                serializer.write_lengthfield(
                    type_lengthfield,
                    self.lengthfield,
                    size - self.lengthfield.size(),
                )?;
            } else {
                let max_size = char_size * self.max;
                while string_size < max_size {
                    serializer.write_u8(0x00)?;
                    string_size += std::mem::size_of::<u8>();
                }
                size = serializer.offset() - offset;
            }

            Ok(size)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            let type_lengthfield = parser.read_lengthfield(self.lengthfield)?;

            let char_size = char_size(self.encoding);
            let mut string_size = type_lengthfield;

            if !self.is_dynamic() {
                string_size = char_size * self.max;
            }

            if self.has_termination() {
                string_size -= self.termination().len();
            }

            let mut valid = true;
            if self.has_bom() {
                for item in self.bom() {
                    let value = parser.read_u8()?;
                    if value != item {
                        valid = false;
                        break;
                    }
                    string_size -= std::mem::size_of::<u8>();
                }
            }
            if !valid {
                return Err(SOMTypeError::InvalidPayload(format!(
                    "Invalid String-BOM at offset {}",
                    parser.offset()
                )));
            }

            let value = match self.encoding {
                SOMStringEncoding::Utf8 => {
                    let mut bytes: Vec<u8> = vec![];
                    while string_size >= char_size {
                        bytes.push(parser.read_u8()?);
                        string_size -= char_size;
                    }
                    String::from_utf8(bytes)?
                }
                _ => {
                    let mut bytes: Vec<u16> = vec![];
                    while string_size >= char_size {
                        bytes.push(parser.read_u16(self.endian())?);
                        string_size -= char_size;
                    }
                    String::from_utf16(&bytes)?
                }
            };

            self.value = value.trim_end_matches(char::from(0x00)).to_string();

            if self.has_termination() {
                for item in self.termination() {
                    let value = parser.read_u8()?;
                    if value != item {
                        valid = false;
                        break;
                    }
                }
            }
            if !valid {
                return Err(SOMTypeError::InvalidPayload(format!(
                    "Invalid String-Termination at offset {}",
                    parser.offset()
                )));
            }

            let size = parser.offset() - offset;
            if self.is_dynamic() && (type_lengthfield != (size - self.lengthfield.size())) {
                return Err(SOMTypeError::InvalidPayload(format!(
                    "Invalid Length-Field value {} at offset {}",
                    type_lengthfield, offset
                )));
            }

            self.validate(offset)?;
            Ok(size)
        }

        fn size(&self) -> usize {
            let mut size: usize = 0;

            if self.is_dynamic() {
                size += self.lengthfield.size();
                size += char_size(self.encoding) * self.len();
            } else {
                size += char_size(self.encoding) * self.max;
            }

            size
        }

        fn category(&self) -> SOMTypeCategory {
            if self.is_dynamic() {
                SOMTypeCategory::ExplicitLength
            } else {
                SOMTypeCategory::ImplicitLength
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl SOMTypeWithMeta for SOMStringType {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.meta = Some(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.meta.as_ref()
        }
    }
}

/// Type for a string encoding.
///
/// See also [SOMString]
pub type SOMStringEncoding = strings::SOMStringEncoding;

/// Type for a string format.
///
/// See also [SOMString]
pub type SOMStringFormat = strings::SOMStringFormat;

/// Type for a string.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let mut obj1 = SOMString::fixed(
///     SOMStringEncoding::Utf8,
///     SOMStringFormat::Plain,
///     3, // max
/// );
/// obj1.set(String::from("foo"));
///
/// let mut obj2 = SOMString::dynamic(
///     SOMLengthField::U32,
///     SOMStringEncoding::Utf16Be,
///     SOMStringFormat::WithBOMandTermination,
///     2, // min
///     5, // max
/// );
/// obj2.set(String::from("bar"));
/// ```
pub type SOMString = strings::SOMStringType;

/// Contains the optional types.
pub(crate) mod optionals {
    use super::*;

    #[doc(hidden)]
    const TAG_MASK: u16 = 0x7FFF;

    #[doc(hidden)]
    fn wire_type<T: SOMType>(value: &T) -> Option<usize> {
        match value.category() {
            SOMTypeCategory::FixedLength => match value.size() {
                1 => Some(0),
                2 => Some(1),
                4 => Some(2),
                8 => Some(3),
                _ => None,
            },
            _ => Some(4),
        }
    }

    #[doc(hidden)]
    fn wire_size(wiretype: usize) -> Option<usize> {
        match wiretype {
            0 => Some(1),
            1 => Some(2),
            2 => Some(4),
            3 => Some(8),
            _ => None,
        }
    }

    /// An optional item type.
    #[derive(Debug, Clone)]
    pub struct SOMOptionalTypeItem<T: SOMType> {
        /// The wiretype of the item.
        wiretype: usize,
        /// The key of the item.
        key: usize,
        /// The value of the item.
        value: T,
        /// Singals if the item is required.
        required: bool,
        /// Singals if the item is set.
        set: bool,
    }

    impl<T: SOMType> SOMOptionalTypeItem<T> {
        /// Creates a new item from the given key and value.
        fn from(key: usize, value: T, required: bool) -> Option<Self> {
            if let Some(wiretype) = wire_type(&value) {
                return Some(SOMOptionalTypeItem {
                    wiretype,
                    key,
                    value,
                    required,
                    set: false,
                });
            }

            None
        }

        /// Returns true if the item is marked as set.
        pub(crate) fn is_set(&self) -> bool {
            self.set
        }

        /// Returns a tuple of the item's key and value.
        pub(crate) fn get(&self) -> (usize, &T) {
            (self.key, &self.value)
        }

        #[doc(hidden)]
        fn tag(&self) -> u16 {
            TAG_MASK & (((self.wiretype as u16) << 12) | ((self.key as u16) & 0x0FFF))
        }
    }

    /// An optional type.
    ///
    /// An optional can have its members being partially set.
    #[derive(Debug, Clone)]
    pub struct SOMOptionalType<T: SOMType> {
        /// Optional metadata of the type.
        meta: Option<SOMTypeMeta>,
        /// The lengthfield of the type.
        lengthfield: SOMLengthField,
        /// The members of the type.
        members: Vec<SOMOptionalTypeItem<T>>,
    }

    impl<T: SOMType> SOMOptionalType<T> {
        /// Creates a new optional from the given members.
        pub fn from(lengthfield: SOMLengthField, members: Vec<SOMOptionalTypeItem<T>>) -> Self {
            SOMOptionalType {
                meta: None,
                lengthfield,
                members,
            }
        }

        /// Returns a new required item or an error.
        pub fn required(key: usize, value: T) -> Result<SOMOptionalTypeItem<T>, SOMTypeError> {
            if let Some(result) = SOMOptionalTypeItem::from(key, value, true) {
                return Ok(result);
            }

            Err(SOMTypeError::InvalidType(format!(
                "Unsupported TLV-Type {}",
                key
            )))
        }

        /// Returns a new optional item or an error.
        pub fn optional(key: usize, value: T) -> Result<SOMOptionalTypeItem<T>, SOMTypeError> {
            if let Some(result) = SOMOptionalTypeItem::from(key, value, false) {
                return Ok(result);
            }

            Err(SOMTypeError::InvalidType(format!(
                "Unsupported TLV-Type {}",
                key
            )))
        }

        /// Returns the number of members.
        pub fn len(&self) -> usize {
            self.members.len()
        }

        /// Returns true if the member with the given key is required.
        pub fn is_required(&self, key: usize) -> bool {
            for member in &self.members {
                if (member.key == key) && member.required {
                    return true;
                }
            }

            false
        }

        /// Returns true if the member with the given key is set.
        pub fn is_set(&self, key: usize) -> bool {
            for member in &self.members {
                if (member.key == key) && member.set {
                    return true;
                }
            }

            false
        }

        /// Returns the member with the given key, if any.
        pub fn get(&self, key: usize) -> Option<&T> {
            for member in &self.members {
                if (member.key == key) && member.set {
                    return Some(&member.value);
                }
            }

            None
        }

        /// Returns the mutable member with the given key, if any.
        pub fn get_mut(&mut self, key: usize) -> Option<&mut T> {
            for member in &mut self.members {
                if member.key == key {
                    member.set = true;
                    return Some(&mut member.value);
                }
            }

            None
        }

        /// Clears the set state of all members.
        pub fn clear(&mut self) {
            for member in &mut self.members {
                member.set = false;
            }
        }

        /// Returns the list of members.
        pub(crate) fn members(&self) -> &Vec<SOMOptionalTypeItem<T>> {
            &self.members
        }
    }

    impl<T: SOMType + Any> SOMType for SOMOptionalType<T> {
        fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
            let offset = serializer.offset();

            let type_lengthfield = serializer.promise(self.lengthfield.size())?;

            for member in &self.members {
                if member.set {
                    serializer.write_u16(member.tag(), SOMEndian::Big)?;
                    if member.value.category() == SOMTypeCategory::ImplicitLength {
                        let member_lengthfield = serializer.promise(self.lengthfield.size())?;
                        let member_start = serializer.offset();
                        member.value.serialize(serializer)?;
                        serializer.write_lengthfield(
                            member_lengthfield,
                            self.lengthfield,
                            serializer.offset() - member_start,
                        )?;
                    } else {
                        member.value.serialize(serializer)?;
                    }
                } else if member.required {
                    return Err(SOMTypeError::InvalidType(format!(
                        "Uninitialized required member {} at offset {}",
                        member.key, offset
                    )));
                }
            }

            let size = serializer.offset() - offset;
            serializer.write_lengthfield(
                type_lengthfield,
                self.lengthfield,
                size - self.lengthfield.size(),
            )?;

            Ok(size)
        }

        fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
            let offset = parser.offset();

            let type_lengthfield = parser.read_lengthfield(self.lengthfield)?;
            let type_start = parser.offset();

            self.clear();
            while (parser.offset() - type_start) < type_lengthfield {
                let tag: u16 = parser.read_u16(SOMEndian::Big)? & TAG_MASK;
                let mut found: bool = false;
                for member in &mut self.members {
                    if !member.set && member.tag() == tag {
                        if member.value.category() == SOMTypeCategory::ImplicitLength {
                            let member_lengthfield = parser.read_lengthfield(self.lengthfield)?;
                            let member_start = parser.offset();
                            member.value.parse(parser)?;
                            if parser.offset() != (member_start + member_lengthfield) {
                                return Err(SOMTypeError::InvalidPayload(format!(
                                    "Invalid Length-Field value {} at offset {}",
                                    member_lengthfield, member_start
                                )));
                            }
                        } else {
                            member.value.parse(parser)?;
                        }
                        member.set = true;
                        found = true;
                        break;
                    }
                }

                if !found {
                    let wiretype: usize = ((tag >> 8) & 0xFF) as usize;

                    if let Some(wiresize) = wire_size(wiretype) {
                        parser.skip(wiresize)?;
                    } else {
                        let skip = parser.read_lengthfield(self.lengthfield)?;
                        parser.skip(skip)?;
                    }
                }
            }

            for member in &mut self.members {
                if member.required && !member.set {
                    return Err(SOMTypeError::InvalidPayload(format!(
                        "Uninitialized required member {} at offset {}",
                        member.key, offset
                    )));
                }
            }

            let size = parser.offset() - offset;
            if type_lengthfield != (size - self.lengthfield.size()) {
                return Err(SOMTypeError::InvalidPayload(format!(
                    "Invalid Length-Field value {} at offset {}",
                    type_lengthfield, offset
                )));
            }

            Ok(size)
        }

        fn size(&self) -> usize {
            let mut size: usize = 0;

            size += self.lengthfield.size();
            for member in &self.members {
                if member.set {
                    size += std::mem::size_of::<u16>(); // tag
                    if member.value.category() == SOMTypeCategory::ImplicitLength {
                        size += self.lengthfield.size();
                    }
                    size += member.value.size();
                }
            }

            size
        }

        fn category(&self) -> SOMTypeCategory {
            SOMTypeCategory::ExplicitLength
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl<T: SOMType> SOMTypeWithMeta for SOMOptionalType<T> {
        fn with_meta(mut self, meta: SOMTypeMeta) -> Self {
            self.meta = Some(meta);
            self
        }

        fn meta(&self) -> Option<&SOMTypeMeta> {
            self.meta.as_ref()
        }
    }
}

/// Type for an optional member.
///
/// See also [SOMOptional]
pub type SOMOptionalMember = wrapper::SOMTypeWrapper;

/// Type for an optional.
///
/// Example
/// ```
/// # use someip_payload::som::*;
/// let mut obj = SOMOptional::from(
///     SOMLengthField::U16,
///     vec![
///         SOMOptional::required(1, SOMOptionalMember::Bool(SOMBool::empty()))?,
///         SOMOptional::optional(2, SOMOptionalMember::U16(SOMu16::empty(SOMEndian::Big)))?,
///     ],
/// );
///
/// if let Some(SOMUnionMember::Bool(member)) = obj.get_mut(1) {
///    member.set(true);
/// }
/// # Ok::<(), SOMTypeError>(())
/// ```
pub type SOMOptional = optionals::SOMOptionalType<SOMOptionalMember>;

/// Contains the type wrappers.
pub(crate) mod wrapper {
    use super::*;
    use std::fmt::{Display, Formatter, Result as FmtResult};

    #[doc(hidden)]
    macro_rules! som_type_wrapper {
        ([$($value:tt($type:tt),)*]) => {
            #[derive(Debug, Clone)]
            pub enum SOMTypeWrapper {$($value($type),)*}

            impl SOMType for SOMTypeWrapper {
                fn serialize(&self, serializer: &mut SOMSerializer) -> Result<usize, SOMTypeError> {
                    match self {
                        $(SOMTypeWrapper::$value(obj) => obj.serialize(serializer),)*
                    }
                }

                fn parse(&mut self, parser: &mut SOMParser) -> Result<usize, SOMTypeError> {
                    match self {
                        $(SOMTypeWrapper::$value(obj) => obj.parse(parser),)*
                    }
                }

                fn size(&self) -> usize {
                    match self {
                        $(SOMTypeWrapper::$value(obj) => obj.size(),)*
                    }
                }

                fn category(&self) -> SOMTypeCategory {
                    match self {
                        $(SOMTypeWrapper::$value(obj) => obj.category(),)*
                    }
                }

                fn as_any(&self) -> &dyn Any {
                    self
                }
            }

            impl Display for SOMTypeWrapper {
                fn fmt(&self, f: &mut Formatter) -> FmtResult {
                    let d;

                    match self {
                        $(SOMTypeWrapper::$value(obj) => {d = format!("{}", obj)},)*

                    }

                    write!(f, "{}", d)
                }
            }
        };
    }

    som_type_wrapper!([
        Bool(SOMBool),
        U8(SOMu8),
        I8(SOMi8),
        U16(SOMu16),
        I16(SOMi16),
        U24(SOMu24),
        I24(SOMi24),
        U32(SOMu32),
        I32(SOMi32),
        U64(SOMu64),
        I64(SOMi64),
        F32(SOMf32),
        F64(SOMf64),
        EnumU8(SOMu8Enum),
        EnumU16(SOMu16Enum),
        EnumU32(SOMu32Enum),
        EnumU64(SOMu64Enum),
        Array(SOMArray),
        ArrayBool(SOMBoolArray),
        ArrayU8(SOMu8Array),
        ArrayI8(SOMi8Array),
        ArrayU16(SOMu16Array),
        ArrayI16(SOMi16Array),
        ArrayU24(SOMu24Array),
        ArrayI24(SOMi24Array),
        ArrayU32(SOMu32Array),
        ArrayI32(SOMi32Array),
        ArrayU64(SOMu64Array),
        ArrayI64(SOMi64Array),
        ArrayF32(SOMf32Array),
        ArrayF64(SOMf64Array),
        Struct(SOMStruct),
        Union(SOMUnion),
        String(SOMString),
        Optional(SOMOptional),
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serialize_parse<T: SOMType>(obj1: &T, obj2: &mut T, data: &[u8]) {
        serialize(obj1, data);
        parse(obj2, data);
    }

    fn serialize<T: SOMType>(obj1: &T, data: &[u8]) {
        let size = data.len();
        assert_eq!(size, obj1.size());

        let mut buffer = vec![0u8; size];
        let mut serializer = SOMSerializer::new(&mut buffer[..]);
        assert_eq!(size, obj1.serialize(&mut serializer).unwrap());
        assert_eq!(buffer, data);
    }

    fn parse<T: SOMType>(obj2: &mut T, data: &[u8]) {
        let mut parser = SOMParser::new(data);
        let size = data.len();
        assert_eq!(size, obj2.parse(&mut parser).unwrap());
        assert_eq!(size, obj2.size());
    }

    fn serialize_fail<T: SOMType>(obj: &T, buffer: &mut [u8], error: &str) {
        let mut serializer = SOMSerializer::new(&mut *buffer);
        match obj.serialize(&mut serializer) {
            Err(err) => {
                assert_eq!(format!("{}", err), format!("{}: {}", ERROR_TAG, error));
            }
            _ => panic!(),
        }
    }

    fn parse_fail<T: SOMType>(obj: &mut T, buffer: &[u8], error: &str) {
        let mut parser = SOMParser::new(buffer);
        match obj.parse(&mut parser) {
            Err(err) => {
                assert_eq!(format!("{}", err), format!("{}: {}", ERROR_TAG, error));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_som_primitive() {
        // generic
        {
            let obj = SOMu8::from(1u8);
            assert_eq!(1u8, obj.get().unwrap());

            let mut obj = SOMu8::empty();
            assert_eq!(None, obj.get());
            obj.set(1u8);
            assert_eq!(1u8, obj.get().unwrap());

            let obj = SOMu16::from(SOMEndian::Big, 1u16);
            assert_eq!(1u16, obj.get().unwrap());

            let mut obj = SOMu16::empty(SOMEndian::Big);
            assert_eq!(None, obj.get());
            obj.set(1u16);
            assert_eq!(1u16, obj.get().unwrap());
        }

        // bool
        {
            let obj1 = SOMBool::from(true);
            let mut obj2 = SOMBool::empty();
            serialize_parse(&obj1, &mut obj2, &[0x01]);
            assert!(obj2.get().unwrap());

            let obj1 = SOMBool::from(false);
            let mut obj2 = SOMBool::empty();
            serialize_parse(&obj1, &mut obj2, &[0x00]);
            assert!(!obj2.get().unwrap());

            let mut obj = SOMBool::from(true);
            serialize_fail(
                &obj,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 1",
            );
            parse_fail(
                &mut obj,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 1",
            );

            let mut obj = SOMBool::empty();
            serialize_fail(&obj, &mut [0u8; 1], "Uninitialized Type at offset 0");
            parse_fail(&mut obj, &[0x2], "Invalid Bool value 2 at offset 0");
        }

        // u8
        {
            let obj1 = SOMu8::from(195u8);
            let mut obj2 = SOMu8::empty();
            serialize_parse(&obj1, &mut obj2, &[0xC3]);
            assert_eq!(195u8, obj2.get().unwrap());

            let mut obj = SOMu8::from(195u8);
            serialize_fail(
                &obj,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 1",
            );
            parse_fail(
                &mut obj,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 1",
            );

            let obj = SOMu8::empty();
            serialize_fail(&obj, &mut [0u8; 1], "Uninitialized Type at offset 0");
        }

        // i8
        {
            let obj1 = SOMi8::from(-95i8);
            let mut obj2 = SOMi8::empty();
            serialize_parse(&obj1, &mut obj2, &[0xA1]);
            assert_eq!(-95i8, obj2.get().unwrap());

            let mut obj = SOMi8::from(-95i8);
            serialize_fail(
                &obj,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 1",
            );
            parse_fail(
                &mut obj,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 1",
            );

            let obj = SOMi8::empty();
            serialize_fail(&obj, &mut [0u8; 1], "Uninitialized Type at offset 0");
        }

        // u16
        {
            let obj1 = SOMu16::from(SOMEndian::Big, 49200u16);
            let mut obj2 = SOMu16::empty(SOMEndian::Big);
            serialize_parse(&obj1, &mut obj2, &[0xC0, 0x30]);
            assert_eq!(49200u16, obj2.get().unwrap());

            let obj1 = SOMu16::from(SOMEndian::Little, 49200u16);
            let mut obj2 = SOMu16::empty(SOMEndian::Little);
            serialize_parse(&obj1, &mut obj2, &[0x30, 0xC0]);
            assert_eq!(49200u16, obj2.get().unwrap());

            let mut obj = SOMu16::from(SOMEndian::Big, 49200u16);
            serialize_fail(
                &obj,
                &mut [0u8; 1],
                "Serializer exhausted at offset 0 for Object size 2",
            );
            parse_fail(
                &mut obj,
                &[0u8; 1],
                "Parser exhausted at offset 0 for Object size 2",
            );

            let obj = SOMu16::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // i16
        {
            let obj1 = SOMi16::from(SOMEndian::Big, -9200i16);
            let mut obj2 = SOMi16::empty(SOMEndian::Big);
            serialize_parse(&obj1, &mut obj2, &[0xDC, 0x10]);
            assert_eq!(-9200i16, obj2.get().unwrap());

            let obj1 = SOMi16::from(SOMEndian::Little, -9200i16);
            let mut obj2 = SOMi16::empty(SOMEndian::Little);
            serialize_parse(&obj1, &mut obj2, &[0x10, 0xDC]);
            assert_eq!(-9200i16, obj2.get().unwrap());

            let mut obj = SOMi16::from(SOMEndian::Big, -9200i16);
            serialize_fail(
                &obj,
                &mut [0u8; 1],
                "Serializer exhausted at offset 0 for Object size 2",
            );
            parse_fail(
                &mut obj,
                &[0u8; 1],
                "Parser exhausted at offset 0 for Object size 2",
            );

            let obj = SOMi16::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // u24
        {
            let obj1 = SOMu24::from(SOMEndian::Big, u24::new(12513060u32));
            let mut obj2 = SOMu24::empty(SOMEndian::Big);
            serialize_parse(&obj1, &mut obj2, &[0xBE, 0xEF, 0x24]);
            assert_eq!(u24::new(12513060u32), obj2.get().unwrap());

            let obj1 = SOMu24::from(SOMEndian::Little, u24::new(12513060u32));
            let mut obj2 = SOMu24::empty(SOMEndian::Little);
            serialize_parse(&obj1, &mut obj2, &[0x24, 0xEF, 0xBE]);
            assert_eq!(u24::new(12513060u32), obj2.get().unwrap());

            let mut obj = SOMu24::from(SOMEndian::Big, u24::new(12513060u32));
            serialize_fail(
                &obj,
                &mut [0u8; 2],
                "Serializer exhausted at offset 0 for Object size 3",
            );
            parse_fail(
                &mut obj,
                &[0u8; 2],
                "Parser exhausted at offset 0 for Object size 3",
            );

            let obj = SOMu24::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // i24
        {
            let obj1 = SOMi24::from(SOMEndian::Big, i24::new(-2513060i32));
            let mut obj2 = SOMi24::empty(SOMEndian::Big);
            serialize_parse(&obj1, &mut obj2, &[0xD9, 0xA7, 0x5C]);
            assert_eq!(i24::new(-2513060i32), obj2.get().unwrap());

            let obj1 = SOMi24::from(SOMEndian::Little, i24::new(-2513060i32));
            let mut obj2 = SOMi24::empty(SOMEndian::Little);
            serialize_parse(&obj1, &mut obj2, &[0x5C, 0xA7, 0xD9]);
            assert_eq!(i24::new(-2513060i32), obj2.get().unwrap());

            let mut obj = SOMi24::from(SOMEndian::Big, i24::new(-2513060i32));
            serialize_fail(
                &obj,
                &mut [0u8; 2],
                "Serializer exhausted at offset 0 for Object size 3",
            );
            parse_fail(
                &mut obj,
                &[0u8; 2],
                "Parser exhausted at offset 0 for Object size 3",
            );

            let obj = SOMi24::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // u32
        {
            let obj1 = SOMu32::from(SOMEndian::Big, 3405691582u32);
            let mut obj2 = SOMu32::empty(SOMEndian::Big);
            serialize_parse(&obj1, &mut obj2, &[0xCA, 0xFE, 0xBA, 0xBE]);
            assert_eq!(3405691582u32, obj2.get().unwrap());

            let obj1 = SOMu32::from(SOMEndian::Little, 3405691582u32);
            let mut obj2 = SOMu32::empty(SOMEndian::Little);
            serialize_parse(&obj1, &mut obj2, &[0xBE, 0xBA, 0xFE, 0xCA]);
            assert_eq!(3405691582u32, obj2.get().unwrap());

            let mut obj = SOMu32::from(SOMEndian::Big, 3405691582u32);
            serialize_fail(
                &obj,
                &mut [0u8; 3],
                "Serializer exhausted at offset 0 for Object size 4",
            );
            parse_fail(
                &mut obj,
                &[0u8; 3],
                "Parser exhausted at offset 0 for Object size 4",
            );

            let obj = SOMu32::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // i32
        {
            let obj1 = SOMi32::from(SOMEndian::Big, -405691582i32);
            let mut obj2 = SOMi32::empty(SOMEndian::Big);
            serialize_parse(&obj1, &mut obj2, &[0xE7, 0xD1, 0xA3, 0x42]);
            assert_eq!(-405691582i32, obj2.get().unwrap());

            let obj1 = SOMi32::from(SOMEndian::Little, -405691582i32);
            let mut obj2 = SOMi32::empty(SOMEndian::Little);
            serialize_parse(&obj1, &mut obj2, &[0x42, 0xA3, 0xD1, 0xE7]);
            assert_eq!(-405691582i32, obj2.get().unwrap());

            let mut obj = SOMi32::from(SOMEndian::Big, -405691582i32);
            serialize_fail(
                &obj,
                &mut [0u8; 3],
                "Serializer exhausted at offset 0 for Object size 4",
            );
            parse_fail(
                &mut obj,
                &[0u8; 3],
                "Parser exhausted at offset 0 for Object size 4",
            );

            let obj = SOMi32::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // u64
        {
            let obj1 = SOMu64::from(SOMEndian::Big, 16045704242864831166u64);
            let mut obj2 = SOMu64::empty(SOMEndian::Big);
            serialize_parse(
                &obj1,
                &mut obj2,
                &[0xDE, 0xAD, 0xCA, 0xFE, 0xBE, 0xEF, 0xBA, 0xBE],
            );
            assert_eq!(16045704242864831166u64, obj2.get().unwrap());

            let obj1 = SOMu64::from(SOMEndian::Little, 16045704242864831166u64);
            let mut obj2 = SOMu64::empty(SOMEndian::Little);
            serialize_parse(
                &obj1,
                &mut obj2,
                &[0xBE, 0xBA, 0xEF, 0xBE, 0xFE, 0xCA, 0xAD, 0xDE],
            );
            assert_eq!(16045704242864831166u64, obj2.get().unwrap());

            let mut obj = SOMu64::from(SOMEndian::Big, 16045704242864831166u64);
            serialize_fail(
                &obj,
                &mut [0u8; 7],
                "Serializer exhausted at offset 0 for Object size 8",
            );
            parse_fail(
                &mut obj,
                &[0u8; 7],
                "Parser exhausted at offset 0 for Object size 8",
            );

            let obj = SOMu64::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // i64
        {
            let obj1 = SOMi64::from(SOMEndian::Big, -6045704242864831166i64);
            let mut obj2 = SOMi64::empty(SOMEndian::Big);
            serialize_parse(
                &obj1,
                &mut obj2,
                &[0xAC, 0x19, 0x58, 0x05, 0xCA, 0xF8, 0x45, 0x42],
            );
            assert_eq!(-6045704242864831166i64, obj2.get().unwrap());

            let obj1 = SOMi64::from(SOMEndian::Little, -6045704242864831166i64);
            let mut obj2 = SOMi64::empty(SOMEndian::Little);
            serialize_parse(
                &obj1,
                &mut obj2,
                &[0x42, 0x45, 0xF8, 0xCA, 0x05, 0x58, 0x19, 0xAC],
            );
            assert_eq!(-6045704242864831166i64, obj2.get().unwrap());

            let mut obj = SOMi64::from(SOMEndian::Big, -6045704242864831166i64);
            serialize_fail(
                &obj,
                &mut [0u8; 7],
                "Serializer exhausted at offset 0 for Object size 8",
            );
            parse_fail(
                &mut obj,
                &[0u8; 7],
                "Parser exhausted at offset 0 for Object size 8",
            );

            let obj = SOMi64::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // f32
        {
            let obj1 = SOMf32::from(SOMEndian::Big, 1.0f32);
            let mut obj2 = SOMf32::empty(SOMEndian::Big);
            serialize_parse(&obj1, &mut obj2, &[0x3F, 0x80, 0x00, 0x00]);
            assert_eq!(1.0f32, obj2.get().unwrap());

            let obj1 = SOMf32::from(SOMEndian::Little, 1.0f32);
            let mut obj2 = SOMf32::empty(SOMEndian::Little);
            serialize_parse(&obj1, &mut obj2, &[0x00, 0x00, 0x80, 0x3F]);
            assert_eq!(1.0f32, obj2.get().unwrap());

            let mut obj = SOMf32::from(SOMEndian::Big, 1.0f32);
            serialize_fail(
                &obj,
                &mut [0u8; 3],
                "Serializer exhausted at offset 0 for Object size 4",
            );
            parse_fail(
                &mut obj,
                &[0u8; 3],
                "Parser exhausted at offset 0 for Object size 4",
            );

            let obj = SOMf32::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }

        // f64
        {
            let obj1 = SOMf64::from(SOMEndian::Big, 1.0f64);
            let mut obj2 = SOMf64::empty(SOMEndian::Big);
            serialize_parse(
                &obj1,
                &mut obj2,
                &[0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            );
            assert_eq!(1.0f64, obj2.get().unwrap());

            let obj1 = SOMf64::from(SOMEndian::Little, 1.0f64);
            let mut obj2 = SOMf64::empty(SOMEndian::Little);
            serialize_parse(
                &obj1,
                &mut obj2,
                &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F],
            );
            assert_eq!(1.0f64, obj2.get().unwrap());

            let mut obj = SOMf64::from(SOMEndian::Big, 1.0f64);
            serialize_fail(
                &obj,
                &mut [0u8; 7],
                "Serializer exhausted at offset 0 for Object size 8",
            );
            parse_fail(
                &mut obj,
                &[0u8; 7],
                "Parser exhausted at offset 0 for Object size 8",
            );

            let obj = SOMf64::empty(SOMEndian::Big);
            serialize_fail(&obj, &mut [0u8; 2], "Uninitialized Type at offset 0");
        }
    }

    #[test]
    fn test_som_struct() {
        // empty struct
        {
            let obj1 = SOMStruct::from(vec![]);
            assert_eq!(0, obj1.len());

            let mut obj2 = SOMStruct::from(vec![]);
            serialize_parse(&obj1, &mut obj2, &[]);
            assert_eq!(0, obj2.len());
        }

        // simple struct
        {
            let obj1 = SOMStruct::from(vec![
                SOMStructMember::Bool(SOMBool::from(true)),
                SOMStructMember::U16(SOMu16::from(SOMEndian::Big, 49200u16)),
            ]);
            assert_eq!(2, obj1.len());

            let mut obj2 = SOMStruct::from(vec![
                SOMStructMember::Bool(SOMBool::empty()),
                SOMStructMember::U16(SOMu16::empty(SOMEndian::Big)),
            ]);
            assert_eq!(2, obj2.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x01, // Bool-Member
                    0xC0, 0x30, // U16-Member
                ],
            );
            assert_eq!(2, obj2.len());

            if let Some(SOMStructMember::Bool(sub)) = obj2.get(0) {
                assert!(sub.get().unwrap());
            } else {
                panic!();
            }

            if let Some(SOMStructMember::U16(sub)) = obj2.get(1) {
                assert_eq!(49200u16, sub.get().unwrap());
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 2],
                "Serializer exhausted at offset 1 for Object size 2",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 2],
                "Parser exhausted at offset 1 for Object size 2",
            );
        }

        // complex struct
        {
            let obj1 = SOMStruct::from(vec![
                SOMStructMember::Struct(SOMStruct::from(vec![
                    SOMStructMember::Bool(SOMBool::from(true)),
                    SOMStructMember::U16(SOMu16::from(SOMEndian::Big, 49200u16)),
                ])),
                SOMStructMember::Struct(SOMStruct::from(vec![
                    SOMStructMember::U16(SOMu16::from(SOMEndian::Little, 49200u16)),
                    SOMStructMember::Bool(SOMBool::from(true)),
                ])),
            ]);
            assert_eq!(2, obj1.len());

            let mut obj2 = SOMStruct::from(vec![
                SOMStructMember::Struct(SOMStruct::from(vec![
                    SOMStructMember::Bool(SOMBool::empty()),
                    SOMStructMember::U16(SOMu16::empty(SOMEndian::Big)),
                ])),
                SOMStructMember::Struct(SOMStruct::from(vec![
                    SOMStructMember::U16(SOMu16::empty(SOMEndian::Little)),
                    SOMStructMember::Bool(SOMBool::empty()),
                ])),
            ]);
            assert_eq!(2, obj2.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x01, // Bool-Member
                    0xC0, 0x30, // U16-Member
                    0x30, 0xC0, // U16-Member
                    0x01, // Bool-Member
                ],
            );
            assert_eq!(2, obj2.len());

            if let Some(SOMStructMember::Struct(sub)) = obj2.get(0) {
                if let Some(SOMStructMember::Bool(subsub)) = sub.get(0) {
                    assert!(subsub.get().unwrap());
                } else {
                    panic!();
                }

                if let Some(SOMStructMember::U16(subsub)) = sub.get(1) {
                    assert_eq!(49200u16, subsub.get().unwrap());
                } else {
                    panic!();
                }
            } else {
                panic!();
            }

            if let Some(SOMStructMember::Struct(sub)) = obj2.get(1) {
                if let Some(SOMStructMember::U16(subsub)) = sub.get(0) {
                    assert_eq!(49200u16, subsub.get().unwrap());
                } else {
                    panic!();
                }

                if let Some(SOMStructMember::Bool(subsub)) = sub.get(1) {
                    assert!(subsub.get().unwrap());
                } else {
                    panic!();
                }
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 5],
                "Serializer exhausted at offset 5 for Object size 1",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 5],
                "Parser exhausted at offset 5 for Object size 1",
            );
        }

        // struct with array
        {
            let obj1 = SOMStruct::from(vec![SOMStructMember::ArrayU16(SOMu16Array::from(
                SOMLengthField::None,
                3,
                3,
                vec![
                    SOMu16::from(SOMEndian::Big, 1u16),
                    SOMu16::from(SOMEndian::Big, 2u16),
                    SOMu16::from(SOMEndian::Big, 3u16),
                ],
            ))]);
            assert_eq!(1, obj1.len());

            let mut obj2 = SOMStruct::from(vec![SOMStructMember::ArrayU16(SOMu16Array::fixed(
                SOMu16::empty(SOMEndian::Big),
                3,
            ))]);
            assert_eq!(1, obj2.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x01, // Array-Member (U16)
                    0x00, 0x02, // Array-Member (U16)
                    0x00, 0x03, // Array-Member (U16)
                ],
            );
            assert_eq!(1, obj2.len());

            if let Some(SOMStructMember::ArrayU16(sub)) = obj2.get(0) {
                assert_eq!(3, sub.len());
                for i in 0..3 {
                    assert_eq!((i + 1) as u16, sub.get(i).unwrap().get().unwrap());
                }
            } else {
                panic!();
            }
        }

        // struct with array of array
        {
            let obj1 = SOMStruct::from(vec![SOMStructMember::Array(SOMArray::from(
                SOMLengthField::U8,
                0,
                3,
                vec![SOMArrayMember::ArrayU8(SOMu8Array::from(
                    SOMLengthField::None,
                    3,
                    3,
                    vec![SOMu8::from(1u8), SOMu8::from(2u8), SOMu8::from(3u8)],
                ))],
            ))]);
            assert_eq!(1, obj1.len());

            let mut obj2 = SOMStruct::from(vec![SOMStructMember::Array(SOMArray::dynamic(
                SOMLengthField::U8,
                SOMArrayMember::ArrayU8(SOMu8Array::fixed(SOMu8::empty(), 3)),
                0,
                3,
            ))]);
            assert_eq!(1, obj2.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x03, // Length-Field (U8)
                    0x01, // Array-Member (U8)
                    0x02, // Array-Member (U8)
                    0x03, // Array-Member (U8)
                ],
            );
            assert_eq!(1, obj2.len());

            if let Some(SOMStructMember::Array(sub)) = obj2.get(0) {
                assert_eq!(1, sub.len());
                if let Some(SOMArrayMember::ArrayU8(subsub)) = sub.get(0) {
                    assert_eq!(3, subsub.len());
                    for i in 0..3 {
                        assert_eq!((i + 1) as u8, subsub.get(i).unwrap().get().unwrap());
                    }
                } else {
                    panic!();
                }
            } else {
                panic!();
            }
        }

        //  struct with union
        {
            let mut obj1 = SOMStruct::from(vec![SOMStructMember::Union(SOMUnion::from(
                SOMTypeField::U8,
                vec![
                    SOMUnionMember::Bool(SOMBool::from(true)),
                    SOMUnionMember::U16(SOMu16::from(SOMEndian::Big, 49200u16)),
                ],
            ))]);
            assert_eq!(1, obj1.len());

            if let Some(SOMStructMember::Union(sub)) = obj1.get_mut(0) {
                assert!(sub.set(2));
            } else {
                panic!();
            }

            let mut obj2 = SOMStruct::from(vec![SOMStructMember::Union(SOMUnion::from(
                SOMTypeField::U8,
                vec![
                    SOMUnionMember::Bool(SOMBool::empty()),
                    SOMUnionMember::U16(SOMu16::empty(SOMEndian::Big)),
                ],
            ))]);
            assert_eq!(1, obj2.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x02, // Type-Field (U8)
                    0xC0, 0x30, // U16-Value
                ],
            );
            assert_eq!(1, obj2.len());

            if let Some(SOMStructMember::Union(sub)) = obj2.get(0) {
                if let Some(SOMUnionMember::U16(subsub)) = sub.get() {
                    assert_eq!(49200u16, subsub.get().unwrap());
                } else {
                    panic!();
                }
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 1",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 1",
            );
        }

        //  struct with enum
        {
            let mut obj1 = SOMStruct::from(vec![SOMStructMember::EnumU16(SOMu16Enum::from(
                SOMEndian::Little,
                vec![SOMu16EnumItem::from(String::from("A"), 49200u16)],
            ))]);
            assert_eq!(1, obj1.len());

            if let Some(SOMStructMember::EnumU16(sub)) = obj1.get_mut(0) {
                assert!(sub.set(String::from("A")));
            } else {
                panic!();
            }

            let mut obj2 = SOMStruct::from(vec![SOMStructMember::EnumU16(SOMu16Enum::from(
                SOMEndian::Little,
                vec![SOMu16EnumItem::from(String::from("A"), 49200u16)],
            ))]);
            assert_eq!(1, obj2.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x30, 0xC0, // U16-Value
                ],
            );
            assert_eq!(1, obj2.len());

            if let Some(SOMStructMember::EnumU16(sub)) = obj2.get(0) {
                assert_eq!(49200u16, sub.get_value().unwrap());
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 2",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 2",
            );
        }

        // struct with string
        {
            let mut obj1 = SOMStruct::from(vec![
                SOMStructMember::String(SOMString::from(
                    SOMLengthField::None,
                    SOMStringEncoding::Utf8,
                    SOMStringFormat::Plain,
                    3,
                    3,
                    String::from("foo"),
                )),
                SOMStructMember::String(SOMString::from(
                    SOMLengthField::U8,
                    SOMStringEncoding::Utf16Be,
                    SOMStringFormat::Plain,
                    1,
                    3,
                    String::from("bar"),
                )),
            ]);
            assert_eq!(2, obj1.len());

            let mut obj2 = SOMStruct::from(vec![
                SOMStructMember::String(SOMString::fixed(
                    SOMStringEncoding::Utf8,
                    SOMStringFormat::Plain,
                    3,
                )),
                SOMStructMember::String(SOMString::dynamic(
                    SOMLengthField::U8,
                    SOMStringEncoding::Utf16Be,
                    SOMStringFormat::Plain,
                    1,
                    3,
                )),
            ]);
            assert_eq!(2, obj2.len());

            if let Some(SOMStructMember::String(sub)) = obj1.get_mut(0) {
                assert!(sub.set(String::from("foo")));
            } else {
                panic!();
            }

            if let Some(SOMStructMember::String(sub)) = obj1.get_mut(1) {
                assert!(sub.set(String::from("bar")));
            } else {
                panic!();
            }

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x66, 0x6F, 0x6F, // String-Member (UTF8)
                    0x06, // Length-Field (U8)
                    0x00, 0x62, 0x00, 0x61, 0x00, 0x72, // String-Member (UTF16)
                ],
            );
            assert_eq!(2, obj2.len());

            if let Some(SOMStructMember::String(sub)) = obj2.get(0) {
                assert_eq!(String::from("foo"), sub.get());
            } else {
                panic!();
            }

            if let Some(SOMStructMember::String(sub)) = obj2.get(1) {
                assert_eq!(String::from("bar"), sub.get());
            } else {
                panic!();
            }
        }

        // struct with optional
        {
            let mut obj1 = SOMStruct::from(vec![SOMStructMember::Optional(SOMOptional::from(
                SOMLengthField::U32,
                vec![SOMOptional::required(1, SOMOptionalMember::Bool(SOMBool::empty())).unwrap()],
            ))]);
            assert_eq!(1, obj1.len());

            if let Some(SOMStructMember::Optional(sub)) = obj1.get_mut(0) {
                if let Some(SOMOptionalMember::Bool(subsub)) = sub.get_mut(1) {
                    subsub.set(true);
                } else {
                    panic!();
                }
            } else {
                panic!();
            }

            let mut obj2 = SOMStruct::from(vec![SOMStructMember::Optional(SOMOptional::from(
                SOMLengthField::U32,
                vec![SOMOptional::required(1, SOMOptionalMember::Bool(SOMBool::empty())).unwrap()],
            ))]);
            assert_eq!(1, obj2.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x03, // Length-Field (U32)
                    0x00, 0x01, // TLV-Tag (U16)
                    0x01, // Bool-Member
                ],
            );
            assert_eq!(1, obj2.len());

            if let Some(SOMStructMember::Optional(sub)) = obj2.get(0) {
                assert_eq!(1, sub.len());
                if let Some(SOMStructMember::Bool(subsub)) = sub.get(1) {
                    assert!(subsub.get().unwrap());
                } else {
                    panic!();
                }
            } else {
                panic!();
            }
        }

        // invalid member
        {
            let mut obj = SOMStruct::from(vec![SOMStructMember::Bool(SOMBool::empty())]);

            serialize_fail(&obj, &mut [0u8; 1], "Uninitialized Type at offset 0");
            parse_fail(&mut obj, &[0x2], "Invalid Bool value 2 at offset 0");
        }
    }

    #[test]
    fn test_som_array() {
        // static array
        {
            let mut obj1 = SOMu16Array::fixed(SOMu16::empty(SOMEndian::Big), 3);
            assert!(!obj1.is_dynamic());
            assert_eq!(3, obj1.max());
            assert_eq!(3, obj1.min());
            assert_eq!(0, obj1.len());

            let mut obj2 = obj1.clone();

            for i in 0..obj1.max() {
                obj1.get_mut(i).unwrap().set((i + 1) as u16);
            }
            assert_eq!(3, obj1.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x01, // Array-Member (U16)
                    0x00, 0x02, // Array-Member (U16)
                    0x00, 0x03, // Array-Member (U16)
                ],
            );
            assert!(!obj2.is_dynamic());
            assert_eq!(3, obj2.max());
            assert_eq!(3, obj2.min());
            assert_eq!(3, obj2.len());

            for i in 0..obj2.max() {
                assert_eq!((i + 1) as u16, obj2.get(i).unwrap().get().unwrap());
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 5],
                "Serializer exhausted at offset 4 for Object size 2",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 5],
                "Parser exhausted at offset 4 for Object size 2",
            );

            obj1.clear();
            assert_eq!(0, obj1.len());
        }

        // dynamic array
        {
            let mut obj1 =
                SOMu16Array::dynamic(SOMLengthField::U32, SOMu16::empty(SOMEndian::Big), 1, 3);
            assert!(obj1.is_dynamic());
            assert_eq!(3, obj1.max());
            assert_eq!(1, obj1.min());
            assert_eq!(0, obj1.len());

            let mut obj2 = obj1.clone();

            for i in 0..obj1.max() {
                obj1.get_mut(i).unwrap().set((i + 1) as u16);
            }
            assert_eq!(3, obj1.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x06, // Length-Field (U32)
                    0x00, 0x01, // Array-Member (U16)
                    0x00, 0x02, // Array-Member (U16)
                    0x00, 0x03, // Array-Member (U16)
                ],
            );
            assert!(obj2.is_dynamic());
            assert_eq!(3, obj2.max());
            assert_eq!(1, obj2.min());
            assert_eq!(3, obj2.len());

            for i in 0..obj2.max() {
                assert_eq!((i + 1) as u16, obj2.get(i).unwrap().get().unwrap());
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 3],
                "Serializer exhausted at offset 0 for Object size 4",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 3],
                "Parser exhausted at offset 0 for Object size 4",
            );

            serialize_fail(
                &obj1,
                &mut [0u8; 9],
                "Serializer exhausted at offset 8 for Object size 2",
            );
            parse_fail(
                &mut obj2,
                &[0x00, 0x00, 0x00, 0x01],
                "Parser exhausted at offset 4 for Object size 2",
            );

            obj1.clear();
            assert_eq!(0, obj1.len());
        }

        // partial array
        {
            let mut obj1 =
                SOMu16Array::dynamic(SOMLengthField::U32, SOMu16::empty(SOMEndian::Big), 1, 3);
            assert!(obj1.is_dynamic());
            assert_eq!(3, obj1.max());
            assert_eq!(1, obj1.min());
            assert_eq!(0, obj1.len());

            let mut obj2 = obj1.clone();

            serialize_fail(&obj1, &mut [0u8; 4], "Invalid Array length 0 at offset 0");
            parse_fail(&mut obj2, &[0u8; 4], "Invalid Array length 0 at offset 0");

            obj1.get_mut(0).unwrap().set(1u16);
            assert_eq!(1, obj1.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x02, // Length-Field (U32)
                    0x00, 0x01, // Array-Member (U16)
                ],
            );
            assert!(obj2.is_dynamic());
            assert_eq!(3, obj2.max());
            assert_eq!(1, obj2.min());
            assert_eq!(1, obj2.len());

            assert_eq!(1u16, obj2.get(0).unwrap().get().unwrap());
        }

        // complex array
        {
            let mut obj1 = SOMArray::fixed(
                SOMArrayMember::Struct(SOMStruct::from(vec![
                    SOMStructMember::U8(SOMu8::empty()),
                    SOMStructMember::U16(SOMu16::empty(SOMEndian::Big)),
                ])),
                3,
            );
            assert!(!obj1.is_dynamic());
            assert_eq!(3, obj1.max());
            assert_eq!(3, obj1.min());
            assert_eq!(0, obj1.len());

            let mut obj2 = obj1.clone();

            for i in 0..obj1.max() {
                if let SOMArrayMember::Struct(sub) = obj1.get_mut(i).unwrap() {
                    if let SOMStructMember::U8(subsub) = sub.get_mut(0).unwrap() {
                        subsub.set((i + 1) as u8);
                    }
                    if let SOMStructMember::U16(subsub) = sub.get_mut(1).unwrap() {
                        subsub.set((i + 1) as u16);
                    }
                }
            }

            assert_eq!(3, obj1.len());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x01, // U8-Member
                    0x00, 0x01, // U16-Member
                    0x02, // U8-Member
                    0x00, 0x02, // U16-Member
                    0x03, // U8-Member
                    0x00, 0x03, // U16-Member
                ],
            );
            assert!(!obj2.is_dynamic());
            assert_eq!(3, obj2.max());
            assert_eq!(3, obj2.min());
            assert_eq!(3, obj2.len());

            for i in 0..obj2.max() {
                if let SOMArrayMember::Struct(sub) = obj2.get(i).unwrap() {
                    if let SOMStructMember::U8(subsub) = sub.get(0).unwrap() {
                        assert_eq!((i + 1) as u8, subsub.get().unwrap());
                    } else {
                        panic!();
                    }
                    if let SOMStructMember::U16(subsub) = sub.get(1).unwrap() {
                        assert_eq!((i + 1) as u16, subsub.get().unwrap());
                    } else {
                        panic!();
                    }
                } else {
                    panic!();
                }
            }
        }
    }

    #[test]
    fn test_som_union() {
        // empty union
        {
            let mut obj1 = SOMUnion::from(SOMTypeField::U8, vec![]);
            assert_eq!(0, obj1.len());
            assert!(!obj1.has_value());
            assert!(obj1.get().is_none());
            assert!(obj1.get_mut(1).is_none());

            let mut obj2 = obj1.clone();
            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, // Type-Field (U8)
                ],
            );

            assert_eq!(0, obj2.len());
            assert!(!obj2.has_value());
        }

        // primitive union
        {
            let mut obj1 = SOMUnion::from(
                SOMTypeField::U8,
                vec![
                    SOMUnionMember::Bool(SOMBool::empty()),
                    SOMUnionMember::U16(SOMu16::empty(SOMEndian::Big)),
                ],
            );
            assert_eq!(2, obj1.len());
            assert!(!obj1.has_value());

            let mut obj2 = obj1.clone();
            assert_eq!(2, obj2.len());
            assert!(!obj2.has_value());

            if let Some(SOMUnionMember::U16(sub)) = obj1.get_mut(2) {
                sub.set(49200u16);
            } else {
                panic!();
            }

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x02, // Type-Field (U8)
                    0xC0, 0x30, // U16-Value
                ],
            );

            assert_eq!(2, obj2.len());
            assert!(obj2.has_value());

            if let Some(SOMUnionMember::U16(sub)) = obj2.get() {
                assert_eq!(49200u16, sub.get().unwrap());
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 1",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 1",
            );

            parse_fail(&mut obj2, &[0x03], "Invalid Union index 3 at offset 0");

            obj1.clear();
            assert!(!obj1.has_value());
        }

        // complex union
        {
            let mut obj1 = SOMUnion::from(
                SOMTypeField::U16,
                vec![
                    SOMUnionMember::Bool(SOMBool::empty()),
                    SOMUnionMember::Struct(SOMStruct::from(vec![
                        SOMStructMember::U8(SOMu8::empty()),
                        SOMStructMember::U16(SOMu16::empty(SOMEndian::Big)),
                    ])),
                ],
            );
            assert_eq!(2, obj1.len());
            assert!(!obj1.has_value());

            let mut obj2 = obj1.clone();
            assert_eq!(2, obj2.len());
            assert!(!obj2.has_value());

            if let Some(SOMUnionMember::Struct(sub)) = obj1.get_mut(2) {
                if let Some(SOMStructMember::U8(subsub)) = sub.get_mut(0) {
                    subsub.set(23u8);
                } else {
                    panic!();
                }

                if let Some(SOMStructMember::U16(subsub)) = sub.get_mut(1) {
                    subsub.set(49200u16);
                } else {
                    panic!();
                }
            } else {
                panic!();
            }

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x02, // Type-Field (U16)
                    0x17, // Struct-Value U8-Member
                    0xC0, 0x30, // Struct-Value U16-Member
                ],
            );

            assert_eq!(2, obj2.len());
            assert!(obj2.has_value());

            if let Some(SOMUnionMember::Struct(sub)) = obj2.get() {
                if let Some(SOMStructMember::U8(subsub)) = sub.get(0) {
                    assert_eq!(23u8, subsub.get().unwrap());
                } else {
                    panic!();
                }

                if let Some(SOMStructMember::U16(subsub)) = sub.get(1) {
                    assert_eq!(49200u16, subsub.get().unwrap());
                } else {
                    panic!();
                }
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 2",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 2",
            );

            obj1.clear();
            assert!(!obj1.has_value());
        }
    }

    #[test]
    fn test_som_enum() {
        // empty enum
        {
            let mut obj = SOMu8Enum::from(vec![]);
            assert_eq!(0, obj.len());
            assert!(!obj.has_value());
            assert!(obj.get_value().is_none());
            assert!(!obj.set(String::from("foo")));
            assert!(obj.get_value().is_none());
        }

        // u8 enum
        {
            let mut obj1 = SOMu8Enum::from(vec![
                SOMu8EnumItem::from(String::from("A"), 23u8),
                SOMu8EnumItem::from(String::from("B"), 42u8),
            ]);
            assert_eq!(2, obj1.len());
            assert!(!obj1.has_value());

            let mut obj2 = obj1.clone();
            assert_eq!(2, obj2.len());
            assert!(!obj2.has_value());

            assert!(obj1.set(String::from("A")));
            assert!(obj1.has_value());
            assert_eq!(23u8, obj1.get_value().unwrap());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x17, // U8-Value
                ],
            );

            assert_eq!(2, obj2.len());
            assert!(obj2.has_value());
            assert_eq!(23u8, obj2.get_value().unwrap());

            serialize_fail(
                &obj1,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 1",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 1",
            );

            parse_fail(&mut obj2, &[0u8; 1], "Invalid Enum value 0 at offset 0");

            obj1.clear();
            assert!(!obj1.has_value());
        }

        // u16 enum
        {
            let mut obj1 = SOMu16Enum::from(
                SOMEndian::Big,
                vec![
                    SOMu16EnumItem::from(String::from("A"), 49200u16),
                    SOMu16EnumItem::from(String::from("B"), 49201u16),
                ],
            );
            assert_eq!(2, obj1.len());
            assert!(!obj1.has_value());

            let mut obj2 = obj1.clone();
            assert_eq!(2, obj2.len());
            assert!(!obj2.has_value());

            assert!(obj1.set(String::from("B")));
            assert!(obj1.has_value());
            assert_eq!(49201u16, obj1.get_value().unwrap());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0xC0, 0x31, // U16-Value
                ],
            );

            assert_eq!(2, obj2.len());
            assert!(obj2.has_value());
            assert_eq!(49201u16, obj2.get_value().unwrap());

            serialize_fail(
                &obj1,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 2",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 2",
            );

            parse_fail(&mut obj2, &[0u8; 2], "Invalid Enum value 0 at offset 0");

            obj1.clear();
            assert!(!obj1.has_value());
        }

        // u32 enum
        {
            let mut obj1 = SOMu32Enum::from(
                SOMEndian::Big,
                vec![SOMu32EnumItem::from(String::from("A"), 3405691582u32)],
            );
            let mut obj2 = obj1.clone();
            assert!(obj1.set(String::from("A")));

            serialize_parse(&obj1, &mut obj2, &[0xCA, 0xFE, 0xBA, 0xBE]);
            assert_eq!(3405691582u32, obj2.get_value().unwrap());
        }

        // u64 enum
        {
            let mut obj1 = SOMu64Enum::from(
                SOMEndian::Big,
                vec![SOMu64EnumItem::from(
                    String::from("A"),
                    16045704242864831166u64,
                )],
            );
            let mut obj2 = obj1.clone();
            assert!(obj1.set(String::from("A")));

            serialize_parse(
                &obj1,
                &mut obj2,
                &[0xDE, 0xAD, 0xCA, 0xFE, 0xBE, 0xEF, 0xBA, 0xBE],
            );
            assert_eq!(16045704242864831166u64, obj2.get_value().unwrap());
        }
    }

    #[test]
    fn test_som_string() {
        // empty strings
        {
            let obj1 = SOMString::fixed(SOMStringEncoding::Utf8, SOMStringFormat::Plain, 0);
            assert!(!obj1.is_dynamic());
            assert_eq!(0, obj1.len());
            assert_eq!(0, obj1.size());

            let obj2 = SOMString::dynamic(
                SOMLengthField::U32,
                SOMStringEncoding::Utf8,
                SOMStringFormat::Plain,
                0,
                3,
            );
            assert!(obj2.is_dynamic());
            assert_eq!(0, obj2.len());
            assert_eq!(4, obj2.size());

            let obj3 = SOMString::fixed(
                SOMStringEncoding::Utf8,
                SOMStringFormat::WithBOMandTermination,
                4,
            );
            assert!(!obj3.is_dynamic());
            assert_eq!(4, obj3.len());
            assert_eq!(4, obj3.size());

            let obj4 = SOMString::dynamic(
                SOMLengthField::U32,
                SOMStringEncoding::Utf8,
                SOMStringFormat::WithBOMandTermination,
                4,
                7,
            );
            assert!(obj4.is_dynamic());
            assert_eq!(4, obj4.len());
            assert_eq!(8, obj4.size());

            let obj5 = SOMString::fixed(SOMStringEncoding::Utf16Be, SOMStringFormat::Plain, 0);
            assert!(!obj5.is_dynamic());
            assert_eq!(0, obj5.len());
            assert_eq!(0, obj5.size());

            let obj6 = SOMString::dynamic(
                SOMLengthField::U32,
                SOMStringEncoding::Utf16Be,
                SOMStringFormat::Plain,
                0,
                3,
            );
            assert!(obj6.is_dynamic());
            assert_eq!(0, obj6.len());
            assert_eq!(4, obj6.size());

            let obj7 = SOMString::fixed(
                SOMStringEncoding::Utf16Le,
                SOMStringFormat::WithBOMandTermination,
                5,
            );
            assert!(!obj7.is_dynamic());
            assert_eq!(2, obj7.len());
            assert_eq!(4 + 6, obj7.size());

            let obj8 = SOMString::dynamic(
                SOMLengthField::U32,
                SOMStringEncoding::Utf16Le,
                SOMStringFormat::WithBOMandTermination,
                2,
                5,
            );
            assert!(obj8.is_dynamic());
            assert_eq!(2, obj8.len());
            assert_eq!(8, obj8.size());
        }

        // fixed utf8 string without bom and termination
        {
            let mut obj1 = SOMString::fixed(SOMStringEncoding::Utf8, SOMStringFormat::Plain, 3);
            assert_eq!(0, obj1.len());
            assert_eq!(3, obj1.size());

            let mut obj2 = obj1.clone();

            assert!(obj1.set(String::from("foo")));
            assert_eq!(3, obj1.len());
            assert_eq!(3, obj1.size());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x66, 0x6F, 0x6F, // Content
                ],
            );

            assert_eq!(String::from("foo"), obj2.get());
            assert_eq!(3, obj2.len());
            assert_eq!(3, obj2.size());

            serialize_fail(
                &obj2,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 1",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 1",
            );

            obj1.clear();
            assert_eq!(0, obj1.len());
        }

        // fixed utf8 string with bom and termination
        {
            let mut obj1 = SOMString::fixed(
                SOMStringEncoding::Utf8,
                SOMStringFormat::WithBOMandTermination,
                7,
            );
            assert_eq!(3 + 1, obj1.len());
            assert_eq!(3 + 3 + 1, obj1.size());

            let mut obj2 = obj1.clone();

            assert!(obj1.set(String::from("foo")));
            assert_eq!(3 + 3 + 1, obj1.len());
            assert_eq!(3 + 3 + 1, obj1.size());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0xEF, 0xBB, 0xBF, // BOM
                    0x66, 0x6F, 0x6F, // Content
                    0x00, // Termination
                ],
            );

            assert_eq!(String::from("foo"), obj2.get());
            assert_eq!(3 + 3 + 1, obj2.len());
            assert_eq!(3 + 3 + 1, obj2.size());

            obj1.clear();
            assert_eq!(3 + 1, obj1.len());
        }

        // fixed utf16-be string with bom and termination
        {
            let mut obj1 = SOMString::fixed(
                SOMStringEncoding::Utf16Be,
                SOMStringFormat::WithBOMandTermination,
                5,
            );
            assert_eq!(1 + 1, obj1.len());
            assert_eq!((1 + 3 + 1) * 2, obj1.size());

            let mut obj2 = obj1.clone();

            assert!(obj1.set(String::from("foo")));
            assert_eq!(1 + 3 + 1, obj1.len());
            assert_eq!((1 + 3 + 1) * 2, obj1.size());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0xFE, 0xFF, // BOM
                    0x00, 0x66, 0x00, 0x6F, 0x00, 0x6F, // Content
                    0x00, 0x00, // Termination
                ],
            );

            assert_eq!(String::from("foo"), obj2.get());
            assert_eq!(1 + 3 + 1, obj2.len());
            assert_eq!((1 + 3 + 1) * 2, obj2.size());

            obj1.clear();
            assert_eq!(1 + 1, obj1.len());
        }

        // partial fixed utf16-le string with termination only
        {
            let mut obj1 = SOMString::fixed(
                SOMStringEncoding::Utf16Le,
                SOMStringFormat::WithTermination,
                10,
            );
            assert_eq!(1, obj1.len());
            assert_eq!((9 + 1) * 2, obj1.size());

            let mut obj2 = obj1.clone();

            assert!(obj1.set(String::from("foo")));
            assert_eq!(3 + 1, obj1.len());
            assert_eq!((3 + 6 + 1) * 2, obj1.size());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x66, 0x00, 0x6F, 0x00, 0x6F, 0x00, // Content
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, // Filler
                    0x00, 0x00, // Termination
                ],
            );

            assert_eq!(String::from("foo"), obj2.get());
            assert_eq!(3 + 1, obj2.len());
            assert_eq!((3 + 6 + 1) * 2, obj2.size());

            obj1.clear();
            assert_eq!(1, obj1.len());
        }

        // dynamic utf8 string without bom and termination
        {
            let mut obj1 = SOMString::dynamic(
                SOMLengthField::U32,
                SOMStringEncoding::Utf8,
                SOMStringFormat::Plain,
                0,
                3,
            );
            assert_eq!(0, obj1.len());
            assert_eq!(4, obj1.size());

            let mut obj2 = obj1.clone();

            assert!(obj1.set(String::from("foo")));
            assert_eq!(3, obj1.len());
            assert_eq!(4 + 3, obj1.size());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x03, // Length-Field (U32)
                    0x66, 0x6F, 0x6F, // Content
                ],
            );

            assert_eq!(String::from("foo"), obj2.get());
            assert_eq!(3, obj2.len());
            assert_eq!(4 + 3, obj2.size());

            serialize_fail(
                &obj2,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 4",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 4",
            );

            obj1.clear();
            assert_eq!(0, obj1.len());
        }

        // dynamic utf8 string with bom and termination
        {
            let mut obj1 = SOMString::dynamic(
                SOMLengthField::U32,
                SOMStringEncoding::Utf8,
                SOMStringFormat::WithBOMandTermination,
                4,
                7,
            );
            assert_eq!(3 + 1, obj1.len());
            assert_eq!(4 + 3 + 1, obj1.size());

            let mut obj2 = obj1.clone();

            assert!(obj1.set(String::from("foo")));
            assert_eq!(3 + 3 + 1, obj1.len());
            assert_eq!(4 + 3 + 3 + 1, obj1.size());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x07, // Length-Field (U32)
                    0xEF, 0xBB, 0xBF, // BOM
                    0x66, 0x6F, 0x6F, // Content
                    0x00, // Termination
                ],
            );

            assert_eq!(String::from("foo"), obj2.get());
            assert_eq!(3 + 3 + 1, obj2.len());
            assert_eq!(4 + 3 + 3 + 1, obj2.size());

            obj1.clear();
            assert_eq!(3 + 1, obj1.len());
        }

        // dynamic utf16-be string with bom and termination
        {
            let mut obj1 = SOMString::dynamic(
                SOMLengthField::U32,
                SOMStringEncoding::Utf16Be,
                SOMStringFormat::WithBOMandTermination,
                2,
                5,
            );
            assert_eq!(1 + 1, obj1.len());
            assert_eq!(4 + (1 + 1) * 2, obj1.size());

            let mut obj2 = obj1.clone();

            assert!(obj1.set(String::from("foo")));
            assert_eq!(1 + 3 + 1, obj1.len());
            assert_eq!(4 + (1 + 3 + 1) * 2, obj1.size());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x0A, // Length-Field (U32)
                    0xFE, 0xFF, // BOM
                    0x00, 0x66, 0x00, 0x6F, 0x00, 0x6F, // Content
                    0x00, 0x00, // Termination
                ],
            );

            assert_eq!(String::from("foo"), obj2.get());
            assert_eq!(1 + 3 + 1, obj2.len());
            assert_eq!(4 + (1 + 3 + 1) * 2, obj2.size());

            obj1.clear();
            assert_eq!(1 + 1, obj1.len());
        }

        // partial dynamic utf16-le string with bom only
        {
            let mut obj1 = SOMString::dynamic(
                SOMLengthField::U32,
                SOMStringEncoding::Utf16Le,
                SOMStringFormat::WithBOM,
                0,
                10,
            );
            assert_eq!(1, obj1.len());
            assert_eq!(4 + 2, obj1.size());

            let mut obj2 = obj1.clone();

            assert!(obj1.set(String::from("foo")));
            assert_eq!(1 + 3, obj1.len());
            assert_eq!(4 + (1 + 3) * 2, obj1.size());

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x08, // Length-Field (U32)
                    0xFF, 0xFE, // BOM
                    0x66, 0x00, 0x6F, 0x00, 0x6F, 0x00, // Content
                ],
            );

            assert_eq!(String::from("foo"), obj2.get());
            assert_eq!(1 + 3, obj2.len());
            assert_eq!(4 + (1 + 3) * 2, obj2.size());

            obj1.clear();
            assert_eq!(1, obj1.len());
        }

        // incomplete length
        {
            let mut obj1 = SOMString::fixed(SOMStringEncoding::Utf8, SOMStringFormat::Plain, 3);

            assert!(!obj1.set(String::from("foobar")));
            assert_eq!(0, obj1.len());
            assert_eq!(3, obj1.size());

            assert!(obj1.set(String::from("f")));
            assert_eq!(1, obj1.len());
            assert_eq!(3, obj1.size());

            serialize(&obj1, &[0x66, 0x00, 0x00]);

            let mut obj2 = SOMString::dynamic(
                SOMLengthField::U8,
                SOMStringEncoding::Utf8,
                SOMStringFormat::Plain,
                2,
                3,
            );

            assert!(!obj2.set(String::from("foobar")));
            assert_eq!(0, obj2.len());
            assert_eq!(1, obj2.size());

            assert!(obj2.set(String::from("f")));
            assert_eq!(1, obj2.len());
            assert_eq!(1 + 1, obj2.size());

            serialize_fail(&obj2, &mut [0u8; 2], "Invalid String length 1 at offset 0");
        }
    }

    #[test]
    fn test_som_optional() {
        // empty optional
        {
            let obj1 = SOMOptional::from(SOMLengthField::U32, vec![]);
            assert_eq!(0, obj1.len());

            let mut obj2 = SOMOptional::from(SOMLengthField::U32, vec![]);
            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x00, // Length-Field (U32)
                ],
            );
            assert_eq!(0, obj2.len());
        }

        // simple optional
        {
            let mut obj1 = SOMOptional::from(
                SOMLengthField::U32,
                vec![
                    SOMOptional::required(1, SOMOptionalMember::Bool(SOMBool::empty())).unwrap(),
                    SOMOptional::optional(2, SOMOptionalMember::U16(SOMu16::empty(SOMEndian::Big)))
                        .unwrap(),
                ],
            );
            assert_eq!(2, obj1.len());

            let mut obj2 = obj1.clone();
            assert_eq!(2, obj2.len());

            if let Some(SOMUnionMember::Bool(sub)) = obj1.get_mut(1) {
                sub.set(true);
            } else {
                panic!();
            }

            if let Some(SOMUnionMember::U16(sub)) = obj1.get_mut(2) {
                sub.set(49200u16);
            } else {
                panic!();
            }

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x07, // Length-Field (U32)
                    0x00, 0x01, // TLV-Tag (U16)
                    0x01, // Bool-Member
                    0x10, 0x02, // TLV-Tag (U16)
                    0xC0, 0x30, // U16-Member
                ],
            );

            assert_eq!(2, obj2.len());

            if let Some(SOMStructMember::Bool(sub)) = obj2.get(1) {
                assert!(sub.get().unwrap());
            } else {
                panic!();
            }

            if let Some(SOMStructMember::U16(sub)) = obj2.get(2) {
                assert_eq!(49200u16, sub.get().unwrap());
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 4",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 4",
            );

            obj1.clear();
            assert!(!obj1.is_set(1));
            assert!(!obj1.is_set(2));
        }

        // complex optional
        {
            let mut obj1 = SOMOptional::from(
                SOMLengthField::U32,
                vec![
                    SOMOptional::required(1, SOMOptionalMember::Bool(SOMBool::empty())).unwrap(),
                    SOMOptional::required(
                        2,
                        SOMOptionalMember::String(SOMString::fixed(
                            SOMStringEncoding::Utf8,
                            SOMStringFormat::Plain,
                            3,
                        )),
                    )
                    .unwrap(),
                    SOMOptional::optional(
                        3,
                        SOMOptionalMember::ArrayU16(SOMu16Array::dynamic(
                            SOMLengthField::U8,
                            SOMu16::empty(SOMEndian::Big),
                            1,
                            3,
                        )),
                    )
                    .unwrap(),
                ],
            );
            assert_eq!(3, obj1.len());

            let mut obj2 = obj1.clone();
            assert_eq!(3, obj2.len());

            if let Some(SOMUnionMember::Bool(sub)) = obj1.get_mut(1) {
                sub.set(true);
            } else {
                panic!();
            }

            if let Some(SOMUnionMember::String(sub)) = obj1.get_mut(2) {
                sub.set(String::from("foo"));
            } else {
                panic!();
            }

            if let Some(SOMUnionMember::ArrayU16(sub)) = obj1.get_mut(3) {
                for i in 0..sub.max() {
                    sub.get_mut(i).unwrap().set((i + 1) as u16);
                }
            } else {
                panic!();
            }

            serialize_parse(
                &obj1,
                &mut obj2,
                &[
                    0x00, 0x00, 0x00, 0x15, // Length-Field (U32)
                    0x00, 0x01, // TLV-Tag (U16)
                    0x01, // Bool-Member
                    0x40, 0x02, // TLV-Tag (U16)
                    0x00, 0x00, 0x00, 0x03, // Length-Field (U32)
                    0x66, 0x6F, 0x6F, // String-Member
                    0x40, 0x03, // TLV-Tag (U16)
                    0x06, // Length-Field (U8)
                    0x00, 0x01, // Array-Member (U16)
                    0x00, 0x02, // Array-Member (U16)
                    0x00, 0x03, // Array-Member (U16)
                ],
            );

            assert_eq!(3, obj2.len());

            if let Some(SOMStructMember::Bool(sub)) = obj2.get(1) {
                assert!(sub.get().unwrap());
            } else {
                panic!();
            }

            if let Some(SOMStructMember::String(sub)) = obj2.get(2) {
                assert_eq!(String::from("foo"), sub.get());
            } else {
                panic!();
            }

            if let Some(SOMStructMember::ArrayU16(sub)) = obj2.get(3) {
                assert_eq!(3, sub.len());
                for i in 0..3 {
                    assert_eq!((i + 1) as u16, sub.get(i).unwrap().get().unwrap());
                }
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 0],
                "Serializer exhausted at offset 0 for Object size 4",
            );
            parse_fail(
                &mut obj2,
                &[0u8; 0],
                "Parser exhausted at offset 0 for Object size 4",
            );

            obj1.clear();
            assert!(!obj1.is_set(1));
            assert!(!obj1.is_set(2));
            assert!(!obj1.is_set(3));
        }

        // missing required
        {
            let mut obj1 = SOMOptional::from(
                SOMLengthField::U32,
                vec![
                    SOMOptional::required(1, SOMOptionalMember::Bool(SOMBool::empty())).unwrap(),
                    SOMOptional::required(2, SOMOptionalMember::U16(SOMu16::empty(SOMEndian::Big)))
                        .unwrap(),
                ],
            );
            assert_eq!(2, obj1.len());

            serialize_fail(
                &obj1,
                &mut [0u8; 11],
                "Uninitialized required member 1 at offset 0",
            );

            if let Some(SOMUnionMember::Bool(sub)) = obj1.get_mut(1) {
                sub.set(true);
            } else {
                panic!();
            }

            serialize_fail(
                &obj1,
                &mut [0u8; 11],
                "Uninitialized required member 2 at offset 0",
            );

            parse_fail(
                &mut obj1,
                &[
                    0x00, 0x00, 0x00, 0x00, // Length-Field (U32)
                ],
                "Uninitialized required member 1 at offset 0",
            );

            parse_fail(
                &mut obj1,
                &[
                    0x00, 0x00, 0x00, 0x03, // Length-Field (U32)
                    0x00, 0x01, // TLV-Tag (U16)
                    0x01, // Bool-Member
                ],
                "Uninitialized required member 2 at offset 0",
            );
        }
    }
}
