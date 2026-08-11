use core::ops::{Deref, DerefMut};

/// Toggle is similar to Option, except that even in the Off/"None" case, there is still
/// an owned allocated inner object. This is useful for holding onto pre-allocated objects
/// that can be toggled as enabled.
pub struct Toggle<T> {
    inner: T,
    on: bool,
}

#[cfg(feature = "serde")]
impl<T: ?Sized> serde::Serialize for Toggle<Box<T>> where Box<T>: serde::Serialize {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut struc = serializer.serialize_struct("Toggle", 2)?;
        struc.serialize_field("inner", &self.inner)?;
        struc.serialize_field("on", &self.on)?;
        struc.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, T: ?Sized> serde::Deserialize<'de> for Toggle<Box<T>> where Box<T>: serde::Deserialize<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct ToggleSerde<T> {
            inner: T,
            on: bool,
        }
        let a = ToggleSerde::<Box<T>>::deserialize(deserializer)?;
        Ok(Toggle { inner: a.inner, on: a.on })
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct ToggleSerdeArray<const N: usize> {
    #[serde(with = "serde_bytes")]
    inner: [u8; N],
    on: bool,
}

#[cfg(feature = "serde")]
impl<const N: usize> serde::Serialize for Toggle<[u8; N]> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ToggleSerdeArray { inner: self.inner, on: self.on }.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, const N: usize> serde::Deserialize<'de> for Toggle<[u8; N]> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let res = ToggleSerdeArray::<N>::deserialize(deserializer)?;
        Ok(Toggle { inner: res.inner, on: res.on })
    }
}

impl<T> Toggle<T> {
    pub fn on(inner: T) -> Self {
        Self { inner, on: true }
    }

    pub fn off(inner: T) -> Self {
        Self { inner, on: false }
    }

    pub fn enable(&mut self) {
        self.on = true;
    }

    pub fn is_on(&self) -> bool {
        self.on
    }

    pub fn get(&self) -> Option<&T> {
        if self.on {
            Some(&self.inner)
        } else {
            None
        }
    }
}

impl<T> Deref for Toggle<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for Toggle<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
