pub trait Serialize {
    fn size(&self) -> usize;
    fn serialize(&self, &mut[u8]);
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