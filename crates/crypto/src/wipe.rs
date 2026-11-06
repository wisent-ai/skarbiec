//! Zeroing secrets when they are dropped, and comparing secrets in time that
//! does not depend on where they differ.

/// Overwrite `bytes` with zeros in a way the optimizer may not remove.
pub fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Overwrite `words` with zeros in a way the optimizer may not remove.
pub fn wipe_words<T: Copy + Default>(words: &mut [T]) {
    for word in words.iter_mut() {
        // SAFETY: `word` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(word, T::default()) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Whether `a` and `b` are equal, in time that depends only on their length.
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    // SAFETY: reading a local through a volatile load keeps the comparison
    // from being turned into an early exit.
    let difference = unsafe { std::ptr::read_volatile(&difference) };
    difference == 0
}

/// Bytes that are zeroed when dropped: a key, a shared secret, a plaintext.
/// A copy (`clone`) is itself a `Secret`, zeroed when it is dropped; two are
/// compared in constant time, never with a comparison that stops early.
#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        equal(&self.0, &other.0)
    }
}

impl Eq for Secret {}

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, handed over without zeroing: the caller now owns them.
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Secret({} bytes)", self.0.len())
    }
}
