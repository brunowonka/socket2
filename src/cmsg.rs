use crate::sys;
use std::convert::TryFrom as _;
use std::io::IoSlice;

/// A wrapper around a bufer that can be used to write ancillary control
/// messages.
pub struct CmsgBuffer<B> {
    buffer: B,
    msghdr: libc::msghdr,
    cur_hdr: *const libc::cmsghdr,
}

impl<B: std::fmt::Debug> std::fmt::Debug for CmsgBuffer<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            buffer,
            msghdr: libc::msghdr { msg_controllen, .. },
            cur_hdr: _,
        } = self;
        f.debug_struct("CmsgBuffer")
            .field("buffer", buffer)
            .field("msghdr.msg_controllen", msg_controllen)
            .finish_non_exhaustive()
    }
}

impl<B: AsMut<[u8]> + AsRef<[u8]>> CmsgBuffer<B> {
    /// Creates a new [`CmsgBuffer`] backed by the bytes in `buffer`.
    pub fn new(mut buffer: B) -> Self {
        // libc::msghdr contains unexported padding fields on Fuchsia.
        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        msghdr.msg_control = buffer.as_mut().as_mut_ptr() as *mut _;
        msghdr.msg_controllen = 0;
        Self {
            msghdr,
            cur_hdr: std::ptr::null(),
            buffer,
        }
    }

    /// Pushes a new control message `m` to the buffer.
    pub fn push<M: Cmsg>(&mut self, m: &M) {
        let space = M::space();
        let avail_len = self.avail_len();
        if space > avail_len {
            panic!(
                "can't fit message {:?}: requires {} bytes, only {} available",
                m, space, avail_len
            )
        }
        self.msghdr.msg_controllen += space;
        let nxt_hdr = if self.cur_hdr.is_null() {
            // Safety: msghdr is a valid pointer.
            unsafe { libc::CMSG_FIRSTHDR(&self.msghdr) }
        } else {
            // Safety: msghdr is a validpointer and cur_hdr is not null.
            unsafe { libc::CMSG_NXTHDR(&self.msghdr, self.cur_hdr) }
        };
        // We've just updated msg_controllen to the length necessary to access a
        // next header, we must not have received a null next header.
        assert!(!nxt_hdr.is_null());
        // Safety: nxt_hdr is not null. It points to initialized memory from our
        // backing buffer slice. The header finding functions above guarantee
        // this is aligned. We own a mutable reference to the backing memory,
        // guaranteeing only we have mutable access to it.
        let nxt_hdr = unsafe { &mut *nxt_hdr };

        // Safety: All values are passed by copy.
        let cmsg_len = M::encoded_len();
        *nxt_hdr = libc::cmsghdr {
            cmsg_len,
            cmsg_level: M::LEVEL,
            cmsg_type: M::TYPE,
        };
        // Safety: nxt_hdr is a valid mutable reference.
        let data = unsafe { libc::CMSG_DATA(nxt_hdr) };

        // Safety: We have ensured that the backing buffer has enough space for
        // M::SIZE considering the alignment requirements of the CMSG struct. We
        // currently own a mutable reference to the backing memory, guaranteeing
        // only we have mutable access to it.
        let data = unsafe { std::slice::from_raw_parts_mut(data, M::SIZE as usize) };
        m.write(data);
        // Store the next header value in case we want to push more options
        // after it later.
        self.cur_hdr = nxt_hdr;
    }

    fn avail_len(&self) -> u32 {
        u32::try_from(self.buffer.as_ref().len()).unwrap_or(std::u32::MAX)
            - self.msghdr.msg_controllen
    }
}

impl<B: AsRef<[u8]>> CmsgBuffer<B> {
    pub(crate) fn buffer(&self) -> IoSlice<'_> {
        IoSlice::new(&self.buffer.as_ref()[..self.msghdr.msg_controllen as usize])
    }
}

/// A type that can be encoded as a control message.
pub trait Cmsg: std::fmt::Debug {
    /// The control message's level, encoded in `cmsghdr.cmsg_level`.
    const LEVEL: libc::c_int;
    /// The control message's type, encoded in `cmsghdr.cmsg_type`.
    const TYPE: libc::c_int;
    /// The size of the encoded type, not accounting for any padding or
    /// alignment.
    const SIZE: libc::c_uint;

    /// Returns the required buffer space for this control message, accounting
    /// for message alignment requirements.
    fn space() -> u32 {
        // Safety: All values are passed by copy.
        unsafe { libc::CMSG_SPACE(Self::SIZE) }
    }

    // Returns the informed length of the encoded message accounting for padding
    // and aligment. This is the value reported in `cmsghdr.cmsg_len`.
    fn encoded_len() -> u32 {
        // Safety: All values are passed by copy.
        unsafe { libc::CMSG_LEN(Self::SIZE) }
    }

    /// Writes the control message value into `buffer`.
    ///
    /// `buffer` must be [`Self::SIZE`] bytes long.
    fn write(&self, buffer: &mut [u8]);
}

/// The `IP_TTL` control message.
#[derive(Debug)]
pub struct IpTtl(u8);

impl Cmsg for IpTtl {
    const LEVEL: libc::c_int = libc::IPPROTO_IP;
    const TYPE: libc::c_int = libc::IP_TTL;
    const SIZE: libc::c_uint = std::mem::size_of::<Self>() as libc::c_uint;

    fn write(&self, buffer: &mut [u8]) {
        let IpTtl(ttl) = self;
        buffer[0] = *ttl;
    }
}

/// The `IPV6_PKTINFO` control message.
#[derive(Debug)]
pub struct Ipv6PktInfo {
    /// The address the packet is destined to/received from. Equivalent to
    /// `in6_pktinfo.ipi6_addr`.
    pub addr: std::net::Ipv6Addr,
    /// The interface index the packet is destined to/received from. Equivalent
    /// to `in6_pktinfo.ipi6_ifindex`.
    pub ifindex: u32,
}

impl Cmsg for Ipv6PktInfo {
    const LEVEL: libc::c_int = libc::IPPROTO_IPV6;
    const TYPE: libc::c_int = libc::IPV6_PKTINFO;
    const SIZE: libc::c_uint = std::mem::size_of::<libc::in6_pktinfo>() as libc::c_uint;

    fn write(&self, buffer: &mut [u8]) {
        let Self { addr, ifindex } = self;
        let pktinfo = libc::in6_pktinfo {
            ipi6_addr: sys::to_in6_addr(addr),
            ipi6_ifindex: *ifindex,
        };
        assert_eq!(buffer.len(), Self::SIZE as usize);
        // Safety: `pktinfo` is valid for reads for its size in bytes. `buffer`
        // is valid for write for the same length, as guaranteed by the
        // assertion above. Copy unit is byte, so alignment is okay. The two
        // regions do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &pktinfo as *const libc::in6_pktinfo as *const _,
                buffer.as_mut_ptr(),
                Self::SIZE as usize,
            )
        }
    }
}
