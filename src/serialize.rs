
/// A serialization implementation
///
/// # Example
/// ```
/// // using serialize
/// let size = some_struct.size();
/// let mut buf = vec!(0;size);
/// some_struct.serialize(&mut buf[..]);
/// ```
pub trait Serialize {
    /// Returns the number of bytes needed to serialize the struct
    fn size(&self) -> usize;

    /// Serializes the structs
    ///
    /// # Arguments
    /// * `output` the slice into which the struct should be serialized
    fn serialize(&self, output: &mut[u8]);
}


// Primitive implementations
impl Serialize for u8 {
    fn size(&self) -> usize {
        return 1;
    }

    fn serialize(&self, output: &mut[u8]) {
        output[0] = *self;
    }
}

impl Serialize for u16 {
    fn size(&self) -> usize {
        return 2;
    }

    fn serialize(&self, output: &mut[u8]) {
        output[1] = (*self & 0xFF) as u8;
        output[0] = (*self >> 8 & 0xFF ) as u8;
    }
}

impl Serialize for u32 {
    fn size(&self) -> usize {
        return 4;
    }

    fn serialize(&self, output: &mut[u8]) {
        output[3] = (*self & 0xFF) as u8;
        output[2] = (*self >> 8 & 0xFF ) as u8;
        output[1] = (*self >> 16 & 0xFF) as u8;
        output[0] = (*self >> 24 & 0xFF ) as u8;
    }
}



impl <T> Serialize for [T]
    where T: Serialize {
        fn size(&self) -> usize {
            return 2 + self.len() * self[0].size();
        }

        fn serialize(&self, output: &mut [u8]) {
            (self.len() as u16).serialize(&mut output[..2]);
            let mut start = 2usize;
            for item in self.iter() {
                item.serialize(&mut output[start..start+item.size()]);
                start += item.size();
            }
        }
    }

/// Semi-automatically generates an implementation of `Serialize`
///
/// Generates a Serialize implementation when provided with
///  a series of property names where each property is itself `Serialize`
///
/// # Example
/// ```
/// struct Person {
///     name: String,
///     age: uint
/// }
///
/// impl Serialize for Person {
///     impl_serialize!(name, age);
/// }
/// ```
macro_rules! impl_serialize {
    ( $( $x:ident ),* ) => {
        fn size(&self) -> usize {
            let mut size = 0usize;
            $( size += self.$x.size(); )*
            size
        }

        fn serialize(&self, output: &mut [u8]) {
            let mut pos = 0usize;
            let mut size = 0usize;
            $(
                pos += size;
                size = self.$x.size();
                self.$x.serialize(&mut output[pos..pos+size]);
             )*
        }
    };
}