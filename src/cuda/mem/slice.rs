use crate::cuda::{
    error::{CudaError, CudaResult},
    mem::{device_memory::DeviceMemory, pined_memory::PinedMemory},
    sync, sys,
};

pub enum CudaMemory<T = u8> {
    Host(PinedMemory<T>),
    Device(DeviceMemory<T>),
}

impl<T> CudaMemory<T> {
    pub fn new_pined(len: usize) -> CudaResult<Self> {
        Ok(Self::Host(PinedMemory::new(len)?))
    }

    pub fn new_device(len: usize) -> CudaResult<Self> {
        Ok(Self::Device(DeviceMemory::new(len)?))
    }

    pub fn device_ptr(&self) -> CudaResult<*mut T> {
        match self {
            Self::Host(h) => h.device_ptr(),
            Self::Device(d) => Ok(d.device_ptr()),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Host(h) => h.len(),
            Self::Device(d) => d.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> Option<&[T]> {
        match self {
            Self::Host(h) => Some(h.as_slice()),
            Self::Device(_) => None,
        }
    }

    pub fn as_mut_slice(&mut self) -> Option<&mut [T]> {
        match self {
            Self::Host(h) => Some(h.as_mut_slice()),
            Self::Device(_) => None,
        }
    }

    pub fn is_pined(&self) -> bool {
        matches!(self, Self::Host(_))
    }

    pub fn is_device(&self) -> bool {
        matches!(self, Self::Device(_))
    }

    pub fn sync(&self) -> CudaResult<()> {
        sync()
    }
}
impl<T: Copy> CudaMemory<T> {
    pub fn from_slice_to_device(src: &[T]) -> CudaResult<Self> {
        let mut dst = Self::new_device(src.len())?;
        dst.copy_from_slice(src)?;
        Ok(dst)
    }

    pub fn from_slice_to_pined(src: &[T]) -> CudaResult<Self> {
        let mut dst = Self::new_pined(src.len())?;
        dst.copy_from_slice(src)?;
        Ok(dst)
    }

    pub fn copy_from_slice(&mut self, src: &[T]) -> CudaResult<()> {
        if src.len() != self.len() {
            return Err(CudaError::InvalidValue);
        }

        match self {
            Self::Host(h) => {
                h.as_mut_slice().copy_from_slice(src);
                Ok(())
            }
            Self::Device(d) => d.copy_from_slice(src),
        }
    }

    pub fn copy_to_slice(&self, dst: &mut [T]) -> CudaResult<()> {
        if dst.len() != self.len() {
            return Err(CudaError::InvalidValue);
        }

        match self {
            Self::Host(h) => {
                dst.copy_from_slice(h.as_slice());
                Ok(())
            }
            Self::Device(d) => d.copy_to_slice(dst),
        }
    }

    pub fn copy_to(&self, dst: &mut Self) -> CudaResult<()> {
        if self.len() != dst.len() {
            return Err(CudaError::InvalidValue);
        }

        match (self, dst) {
            (Self::Host(src), Self::Host(dst_h)) => {
                dst_h.as_mut_slice().copy_from_slice(src.as_slice());
                Ok(())
            }
            (Self::Host(src), Self::Device(dst_d)) => dst_d.copy_from_slice(src.as_slice()),
            (Self::Device(src), Self::Host(dst_h)) => src.copy_to_slice(dst_h.as_mut_slice()),
            (Self::Device(src), Self::Device(dst_d)) => unsafe {
                let err = sys::cudaMemcpy(
                    dst_d.device_ptr().cast(),
                    src.device_ptr().cast(),
                    src.len() * size_of::<T>(),
                    sys::cudaMemcpyKind::cudaMemcpyDeviceToDevice,
                );
                CudaError::from(err).into_error(())
            },
        }
    }
}

impl<T: Default + Copy> CudaMemory<T> {
    pub fn to_vec(&self) -> CudaResult<Vec<T>> {
        let mut vec = vec![T::default(); self.len()];
        self.copy_to_slice(&mut vec)?;
        Ok(vec)
    }
}
