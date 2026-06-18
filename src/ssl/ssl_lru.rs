/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org> -- MIT (see LICENSE.txt)
 */

//! LRU session cache (`src/ssl/ssl_lru.c`).
//!
//! Faithful port of the upstream intrusive cache: session entries live in a
//! flat byte block, organised both as a doubly-linked LRU list (eviction from
//! the tail) and a binary search tree keyed on a masked session ID. The session
//! ID is masked with an HMAC (keyed by a random value drawn from the server RNG
//! on first save) to keep the tree balanced against adversarial session reuse.
//!
//! This implements the engine's [`SslSessionCache`] trait, reading/writing the
//! session parameters directly from the engine's `mem[]` (the same fields the
//! handshake interpreter uses).

use crate::hash::br_hash_class;
use crate::inner::{br_dec16be, br_dec32be, br_enc16be, br_enc32be};
use crate::mac::{br_hmac_context, br_hmac_init, br_hmac_key_context, br_hmac_key_init, br_hmac_out};
use crate::rand::br_hmac_drbg_generate;

use super::ssl_engine::*;

const SESSION_ID_LEN: usize = 32;
const MASTER_SECRET_LEN: usize = 48;

const SESSION_ID_OFF: u32 = 0;
const MASTER_SECRET_OFF: u32 = 32;
const VERSION_OFF: u32 = 80;
const CIPHER_SUITE_OFF: u32 = 82;
const LIST_PREV_OFF: u32 = 84;
const LIST_NEXT_OFF: u32 = 88;
const TREE_LEFT_OFF: u32 = 92;
const TREE_RIGHT_OFF: u32 = 96;

const LRU_ENTRY_LEN: u32 = 100;

const ADDR_NULL: u32 = u32::MAX;

/// LRU session cache (`br_ssl_session_cache_lru`).
pub struct br_ssl_session_cache_lru {
    store: Vec<u8>,
    store_len: u32,
    store_ptr: u32,
    init_done: bool,
    index_key: [u8; 32],
    hash: Option<&'static br_hash_class>,
    head: u32,
    tail: u32,
    root: u32,
}

impl br_ssl_session_cache_lru {
    /// see inner.h (`br_ssl_session_cache_lru_init`). `store_len` is the cache
    /// capacity in bytes (each session uses `LRU_ENTRY_LEN` = 100 bytes).
    pub fn new(store_len: usize) -> Self {
        br_ssl_session_cache_lru {
            store: vec![0u8; store_len],
            store_len: store_len as u32,
            store_ptr: 0,
            init_done: false,
            index_key: [0u8; 32],
            hash: None,
            head: ADDR_NULL,
            tail: ADDR_NULL,
            root: ADDR_NULL,
        }
    }

    // ---- intrusive link accessors (GETSET) ----------------------------------
    fn get_field(&self, x: u32, off: u32) -> u32 {
        br_dec32be(&self.store[(x + off) as usize..])
    }
    fn set_field(&mut self, x: u32, off: u32, val: u32) {
        br_enc32be(&mut self.store[(x + off) as usize..], val);
    }
    fn get_prev(&self, x: u32) -> u32 {
        self.get_field(x, LIST_PREV_OFF)
    }
    fn set_prev(&mut self, x: u32, v: u32) {
        self.set_field(x, LIST_PREV_OFF, v)
    }
    fn get_next(&self, x: u32) -> u32 {
        self.get_field(x, LIST_NEXT_OFF)
    }
    fn set_next(&mut self, x: u32, v: u32) {
        self.set_field(x, LIST_NEXT_OFF, v)
    }
    fn get_left(&self, x: u32) -> u32 {
        self.get_field(x, TREE_LEFT_OFF)
    }
    fn set_left(&mut self, x: u32, v: u32) {
        self.set_field(x, TREE_LEFT_OFF, v)
    }
    fn get_right(&self, x: u32) -> u32 {
        self.get_field(x, TREE_RIGHT_OFF)
    }
    fn set_right(&mut self, x: u32, v: u32) {
        self.set_field(x, TREE_RIGHT_OFF, v)
    }

    fn id_slice(&self, x: u32) -> &[u8] {
        let s = (x + SESSION_ID_OFF) as usize;
        &self.store[s..s + SESSION_ID_LEN]
    }

    /// `mask_id`: replace the session ID with a keyed HMAC of itself.
    fn mask_id(&self, src: &[u8], dst: &mut [u8]) {
        dst[..SESSION_ID_LEN].copy_from_slice(&src[..SESSION_ID_LEN]);
        let hash = self.hash.expect("cache hash not initialised");
        let mut hkc = br_hmac_key_context::default();
        br_hmac_key_init(&mut hkc, hash, &self.index_key, self.index_key.len());
        let mut hc = br_hmac_context::new(&hkc, SESSION_ID_LEN);
        br_hmac_init(&mut hc, &hkc, SESSION_ID_LEN);
        crate::mac::br_hmac_update(&mut hc, src, SESSION_ID_LEN);
        br_hmac_out(&hc, &mut dst[..SESSION_ID_LEN]);
    }

    /// `find_node`: locate a node by (masked) ID. Returns `(node_addr,
    /// last_link_addr)`; `last_link_addr` is ADDR_NULL for the root / empty.
    fn find_node(&self, id: &[u8]) -> (u32, u32) {
        let mut x = self.root;
        let mut y = ADDR_NULL;
        while x != ADDR_NULL {
            let r = id[..SESSION_ID_LEN].cmp(self.id_slice(x));
            match r {
                std::cmp::Ordering::Less => {
                    y = x + TREE_LEFT_OFF;
                    x = self.get_left(x);
                }
                std::cmp::Ordering::Equal => return (x, y),
                std::cmp::Ordering::Greater => {
                    y = x + TREE_RIGHT_OFF;
                    x = self.get_right(x);
                }
            }
        }
        (ADDR_NULL, y)
    }

    /// `find_replacement_node`: returns `(node, link_addr)` (both ADDR_NULL if
    /// `x` has no child).
    fn find_replacement_node(&self, x: u32) -> (u32, u32) {
        let mut y1 = self.get_left(x);
        if y1 != ADDR_NULL {
            let mut y2 = x + TREE_LEFT_OFF;
            loop {
                let z = self.get_right(y1);
                if z == ADDR_NULL {
                    return (y1, y2);
                }
                y2 = y1 + TREE_RIGHT_OFF;
                y1 = z;
            }
        }
        y1 = self.get_right(x);
        if y1 != ADDR_NULL {
            let mut y2 = x + TREE_RIGHT_OFF;
            loop {
                let z = self.get_left(y1);
                if z == ADDR_NULL {
                    return (y1, y2);
                }
                y2 = y1 + TREE_LEFT_OFF;
                y1 = z;
            }
        }
        (ADDR_NULL, ADDR_NULL)
    }

    /// `set_link`: point link at `alx` to `x` (ADDR_NULL => set tree root).
    fn set_link(&mut self, alx: u32, x: u32) {
        if alx == ADDR_NULL {
            self.root = x;
        } else {
            br_enc32be(&mut self.store[alx as usize..], x);
        }
    }

    /// `remove_node`: unlink `x` from the binary tree.
    fn remove_node(&mut self, x: u32) {
        let id: Vec<u8> = self.id_slice(x).to_vec();
        let (_, alx) = self.find_node(&id);
        let (y, aly) = self.find_replacement_node(x);
        if y != ADDR_NULL {
            let mut z = self.get_left(y);
            if z == ADDR_NULL {
                z = self.get_right(y);
            }
            self.set_link(aly, z);
            self.set_link(alx, y);
            let lx = self.get_left(x);
            let rx = self.get_right(x);
            self.set_left(y, lx);
            self.set_right(y, rx);
        } else {
            self.set_link(alx, ADDR_NULL);
        }
    }
}

impl SslSessionCache for br_ssl_session_cache_lru {
    /// `lru_load`
    fn load(&mut self, eng: &mut br_ssl_engine_context) -> bool {
        if !self.init_done {
            return false;
        }
        let src_id: Vec<u8> = eng.mem[OFF_SESSION_ID..OFF_SESSION_ID + SESSION_ID_LEN].to_vec();
        let mut id = [0u8; SESSION_ID_LEN];
        self.mask_id(&src_id, &mut id);
        let (x, _) = self.find_node(&id);
        if x == ADDR_NULL {
            return false;
        }
        let version = br_dec16be(&self.store[(x + VERSION_OFF) as usize..]) as u16;
        if version == 0 {
            // Disabled entry: pretend not found, and don't touch the LRU list.
            return false;
        }
        let cipher_suite = br_dec16be(&self.store[(x + CIPHER_SUITE_OFF) as usize..]) as u16;
        eng.set16(OFF_SESSION_VERSION, version);
        eng.set16(OFF_SESSION_CIPHER_SUITE, cipher_suite);
        let ms_off = (x + MASTER_SECRET_OFF) as usize;
        eng.mem[OFF_SESSION_MASTER_SECRET..OFF_SESSION_MASTER_SECRET + MASTER_SECRET_LEN]
            .copy_from_slice(&self.store[ms_off..ms_off + MASTER_SECRET_LEN]);
        // Move the found node to the list head (LRU promotion).
        if x != self.head {
            let p = self.get_prev(x);
            let n = self.get_next(x);
            self.set_next(p, n);
            if n == ADDR_NULL {
                self.tail = p;
            } else {
                self.set_prev(n, p);
            }
            let head = self.head;
            self.set_prev(head, x);
            self.set_next(x, head);
            self.set_prev(x, ADDR_NULL);
            self.head = x;
        }
        true
    }

    /// `lru_save`
    fn save(&mut self, eng: &mut br_ssl_engine_context) {
        if self.store_len < LRU_ENTRY_LEN {
            return;
        }
        if !self.init_done {
            if let Some(rng) = eng.rng.as_mut() {
                br_hmac_drbg_generate(rng, &mut self.index_key, 32);
                self.hash = Some(rng.digest_class);
            } else {
                return;
            }
            self.init_done = true;
        }
        let src_id: Vec<u8> = eng.mem[OFF_SESSION_ID..OFF_SESSION_ID + SESSION_ID_LEN].to_vec();
        let mut id = [0u8; SESSION_ID_LEN];
        self.mask_id(&src_id, &mut id);

        // Reject ID collisions (exceedingly rare).
        if self.find_node(&id).0 != ADDR_NULL {
            return;
        }

        // Allocate room or evict the LRU tail.
        let x;
        if self.store_ptr > self.store_len - LRU_ENTRY_LEN {
            x = self.tail;
            self.tail = self.get_prev(x);
            if self.tail == ADDR_NULL {
                self.head = ADDR_NULL;
            } else {
                self.set_next(self.tail, ADDR_NULL);
            }
            self.remove_node(x);
        } else {
            x = self.store_ptr;
            self.store_ptr += LRU_ENTRY_LEN;
        }

        // Link the new node into the tree.
        let (_, alx) = self.find_node(&id);
        self.set_link(alx, x);
        self.set_left(x, ADDR_NULL);
        self.set_right(x, ADDR_NULL);

        // New entry becomes the list head.
        if self.head == ADDR_NULL {
            self.tail = x;
        } else {
            let head = self.head;
            self.set_prev(head, x);
        }
        self.set_prev(x, ADDR_NULL);
        self.set_next(x, self.head);
        self.head = x;

        // Fill in the entry data.
        let idoff = (x + SESSION_ID_OFF) as usize;
        self.store[idoff..idoff + SESSION_ID_LEN].copy_from_slice(&id);
        let msoff = (x + MASTER_SECRET_OFF) as usize;
        self.store[msoff..msoff + MASTER_SECRET_LEN].copy_from_slice(
            &eng.mem[OFF_SESSION_MASTER_SECRET..OFF_SESSION_MASTER_SECRET + MASTER_SECRET_LEN],
        );
        let version = eng.get16(OFF_SESSION_VERSION);
        let cs = eng.get16(OFF_SESSION_CIPHER_SUITE);
        br_enc16be(&mut self.store[(x + VERSION_OFF) as usize..], version as u32);
        br_enc16be(&mut self.store[(x + CIPHER_SUITE_OFF) as usize..], cs as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{br_multihash_setimpl, br_sha256_ID, br_sha256_vtable};

    /// Build a bare engine with an initialised RNG and a session populated
    /// directly in mem[] (id, version, cipher suite, master secret).
    fn engine_with_session(id_byte: u8, ms_byte: u8, cs: u16) -> br_ssl_engine_context {
        let mut eng = br_ssl_engine_context::new();
        br_multihash_setimpl(&mut eng.mhash, br_sha256_ID as i32, Some(&br_sha256_vtable));
        eng.inject_entropy(&[0x42u8; 32]);
        for i in 0..SESSION_ID_LEN {
            eng.mem[OFF_SESSION_ID + i] = id_byte;
        }
        eng.set8(OFF_SESSION_ID_LEN, 32);
        eng.set16(OFF_SESSION_VERSION, BR_TLS12);
        eng.set16(OFF_SESSION_CIPHER_SUITE, cs);
        for i in 0..MASTER_SECRET_LEN {
            eng.mem[OFF_SESSION_MASTER_SECRET + i] = ms_byte;
        }
        eng
    }

    #[test]
    fn lru_save_load_roundtrip() {
        let mut cache = br_ssl_session_cache_lru::new(64 * LRU_ENTRY_LEN as usize);
        let mut eng = engine_with_session(0xAB, 0xCD, 0xC02F);
        cache.save(&mut eng);

        // Clear the session params, then load by the same session id.
        let mut eng2 = engine_with_session(0xAB, 0x00, 0x0000);
        eng2.set16(OFF_SESSION_VERSION, 0);
        eng2.set16(OFF_SESSION_CIPHER_SUITE, 0);
        // Reuse the first cache's index key by sharing the cache instance.
        assert!(cache.load(&mut eng2), "session must be found");
        assert_eq!(eng2.get16(OFF_SESSION_VERSION), BR_TLS12);
        assert_eq!(eng2.get16(OFF_SESSION_CIPHER_SUITE), 0xC02F);
        assert!(
            eng2.mem[OFF_SESSION_MASTER_SECRET..OFF_SESSION_MASTER_SECRET + MASTER_SECRET_LEN]
                .iter()
                .all(|&b| b == 0xCD),
            "master secret restored"
        );
    }

    #[test]
    fn lru_miss_for_unknown_id() {
        let mut cache = br_ssl_session_cache_lru::new(64 * LRU_ENTRY_LEN as usize);
        let mut eng = engine_with_session(0x11, 0x22, 0xC02F);
        cache.save(&mut eng);
        // A different session id must not be found.
        let mut other = engine_with_session(0x99, 0x00, 0x0000);
        assert!(!cache.load(&mut other), "unknown session must miss");
    }

    #[test]
    fn lru_eviction_keeps_capacity() {
        // Capacity for 3 entries; insert 5 distinct sessions; the cache must
        // not grow past capacity and the most-recently-used must survive.
        let mut cache = br_ssl_session_cache_lru::new(3 * LRU_ENTRY_LEN as usize);
        for i in 0..5u8 {
            let mut eng = engine_with_session(i, i.wrapping_add(0x40), 0xC02F);
            cache.save(&mut eng);
        }
        assert!(cache.store_ptr <= 3 * LRU_ENTRY_LEN, "cache stayed within capacity");
        // The last inserted session (id byte 4) must still be present.
        let mut q = engine_with_session(4, 0x00, 0x0000);
        assert!(cache.load(&mut q), "most-recent entry retained");
    }
}
