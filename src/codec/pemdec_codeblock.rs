// The upstream `t0_datablock[]` is 21 bytes; the "----END " string (offset 13)
// has no in-array NUL terminator. In the compiled C binary the very next byte
// is `t0_codeblock[0]`, which is 0x00, so the string scan in `match-string`
// terminates there. We reproduce that adjacency with an explicit trailing 0x00.
static T0_DATABLOCK: [u8; 22] = [
    0x00, 0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20,
    0x00, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44, 0x20, 0x00,
];

static T0_CODEBLOCK: [u8; 612] = [
    0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x01, 0x01, 0x07, 0x00, 0x00, 0x01,
    0x01, 0x08, 0x00, 0x00, 0x13, 0x13, 0x00, 0x00, 0x01, 0x82, 0x40, 0x00,
    0x00, 0x01, 0x82, 0x41, 0x00, 0x00, 0x05, 0x14, 0x2C, 0x14, 0x01, 0x0A,
    0x0D, 0x06, 0x03, 0x13, 0x04, 0x76, 0x01, 0x2D, 0x0C, 0x06, 0x05, 0x2E,
    0x01, 0x03, 0x2D, 0x00, 0x01, 0x0D, 0x27, 0x05, 0x04, 0x01, 0x03, 0x2D,
    0x00, 0x15, 0x2E, 0x01, 0x02, 0x2D, 0x00, 0x01, 0x01, 0x7F, 0x03, 0x00,
    0x25, 0x01, 0x00, 0x18, 0x0D, 0x06, 0x03, 0x13, 0x04, 0x3C, 0x01, 0x7F,
    0x18, 0x0D, 0x06, 0x13, 0x13, 0x02, 0x00, 0x05, 0x06, 0x2E, 0x01, 0x03,
    0x2D, 0x04, 0x03, 0x01, 0x7F, 0x23, 0x01, 0x00, 0x00, 0x04, 0x23, 0x01,
    0x01, 0x18, 0x0D, 0x06, 0x09, 0x13, 0x01, 0x00, 0x23, 0x01, 0x00, 0x00,
    0x04, 0x14, 0x01, 0x02, 0x18, 0x0D, 0x06, 0x06, 0x13, 0x01, 0x7F, 0x00,
    0x04, 0x08, 0x13, 0x01, 0x03, 0x2D, 0x01, 0x00, 0x00, 0x13, 0x01, 0x00,
    0x03, 0x00, 0x04, 0xFF, 0x33, 0x01, 0x2C, 0x14, 0x01, 0x2D, 0x0D, 0x06,
    0x04, 0x13, 0x01, 0x7F, 0x00, 0x14, 0x31, 0x06, 0x02, 0x13, 0x29, 0x14,
    0x01, 0x0A, 0x0D, 0x06, 0x04, 0x13, 0x01, 0x02, 0x00, 0x16, 0x14, 0x1D,
    0x06, 0x05, 0x13, 0x2E, 0x01, 0x03, 0x00, 0x03, 0x00, 0x29, 0x14, 0x01,
    0x0A, 0x0D, 0x06, 0x04, 0x13, 0x01, 0x03, 0x00, 0x16, 0x14, 0x1D, 0x06,
    0x05, 0x13, 0x2E, 0x01, 0x03, 0x00, 0x02, 0x00, 0x01, 0x06, 0x0A, 0x07,
    0x03, 0x00, 0x29, 0x14, 0x01, 0x0A, 0x0D, 0x06, 0x04, 0x13, 0x01, 0x03,
    0x00, 0x14, 0x01, 0x3D, 0x0D, 0x06, 0x2E, 0x13, 0x29, 0x14, 0x01, 0x0A,
    0x0D, 0x06, 0x04, 0x13, 0x01, 0x03, 0x00, 0x2F, 0x05, 0x04, 0x13, 0x01,
    0x03, 0x00, 0x01, 0x3D, 0x0C, 0x06, 0x03, 0x01, 0x03, 0x00, 0x02, 0x00,
    0x01, 0x0F, 0x10, 0x06, 0x03, 0x01, 0x03, 0x00, 0x02, 0x00, 0x01, 0x04,
    0x0F, 0x1C, 0x01, 0x01, 0x00, 0x16, 0x14, 0x1D, 0x06, 0x05, 0x13, 0x2E,
    0x01, 0x03, 0x00, 0x02, 0x00, 0x01, 0x06, 0x0A, 0x07, 0x03, 0x00, 0x29,
    0x14, 0x01, 0x0A, 0x0D, 0x06, 0x04, 0x13, 0x01, 0x03, 0x00, 0x14, 0x01,
    0x3D, 0x0D, 0x06, 0x20, 0x13, 0x2F, 0x05, 0x03, 0x01, 0x03, 0x00, 0x02,
    0x00, 0x01, 0x03, 0x10, 0x06, 0x03, 0x01, 0x03, 0x00, 0x02, 0x00, 0x01,
    0x0A, 0x0F, 0x1C, 0x02, 0x00, 0x01, 0x02, 0x0F, 0x1C, 0x01, 0x01, 0x00,
    0x16, 0x14, 0x1D, 0x06, 0x05, 0x13, 0x2E, 0x01, 0x03, 0x00, 0x02, 0x00,
    0x01, 0x06, 0x0A, 0x07, 0x03, 0x00, 0x02, 0x00, 0x01, 0x10, 0x0F, 0x1C,
    0x02, 0x00, 0x01, 0x08, 0x0F, 0x1C, 0x02, 0x00, 0x1C, 0x01, 0x00, 0x00,
    0x00, 0x28, 0x01, 0x01, 0x2D, 0x24, 0x06, 0x02, 0x04, 0x7B, 0x04, 0x75,
    0x00, 0x14, 0x12, 0x2A, 0x14, 0x05, 0x04, 0x20, 0x01, 0x7F, 0x00, 0x2C,
    0x2A, 0x14, 0x01, 0x0A, 0x0D, 0x06, 0x05, 0x13, 0x20, 0x01, 0x00, 0x00,
    0x0D, 0x05, 0x05, 0x13, 0x2E, 0x01, 0x00, 0x00, 0x1E, 0x04, 0x5E, 0x00,
    0x01, 0x01, 0x27, 0x06, 0x0B, 0x22, 0x01, 0x80, 0x7F, 0x2B, 0x14, 0x06,
    0x02, 0x30, 0x00, 0x13, 0x04, 0x6E, 0x00, 0x2C, 0x14, 0x31, 0x05, 0x01,
    0x00, 0x13, 0x04, 0x77, 0x00, 0x14, 0x14, 0x01, 0x80, 0x61, 0x0E, 0x1B,
    0x01, 0x80, 0x7A, 0x0B, 0x10, 0x06, 0x03, 0x01, 0x20, 0x08, 0x00, 0x01,
    0x14, 0x03, 0x00, 0x1B, 0x18, 0x05, 0x05, 0x20, 0x2E, 0x01, 0x00, 0x00,
    0x2C, 0x14, 0x01, 0x0A, 0x0D, 0x06, 0x06, 0x20, 0x02, 0x00, 0x1B, 0x08,
    0x00, 0x14, 0x01, 0x0D, 0x0D, 0x06, 0x03, 0x13, 0x04, 0x03, 0x2A, 0x18,
    0x1A, 0x1E, 0x1B, 0x1F, 0x1B, 0x04, 0x59, 0x00, 0x19, 0x14, 0x1D, 0x05,
    0x01, 0x00, 0x13, 0x11, 0x04, 0x76, 0x00, 0x21, 0x1A, 0x11, 0x00, 0x00,
    0x2C, 0x01, 0x0A, 0x0C, 0x06, 0x02, 0x04, 0x78, 0x00, 0x01, 0x01, 0x7F,
    0x03, 0x00, 0x2C, 0x14, 0x01, 0x0A, 0x0C, 0x06, 0x09, 0x31, 0x05, 0x04,
    0x01, 0x00, 0x03, 0x00, 0x04, 0x70, 0x13, 0x02, 0x00, 0x00, 0x00, 0x14,
    0x06, 0x14, 0x1F, 0x14, 0x22, 0x07, 0x17, 0x01, 0x2D, 0x0C, 0x06, 0x08,
    0x22, 0x07, 0x1E, 0x01, 0x00, 0x1B, 0x1A, 0x00, 0x04, 0x69, 0x22, 0x1A,
    0x00, 0x00, 0x14, 0x01, 0x0A, 0x0C, 0x1B, 0x01, 0x20, 0x0B, 0x10, 0x00,
];

static T0_CADDR: [u16; 21] = [
    0, 5, 10, 15, 19, 24, 29, 67, 149, 384, 396, 431, 450, 460, 479, 523, 534,
    539, 549, 574, 601,
];

const T0_INTERPRETED: u32 = 29;
const INIT_MAIN_SLOT: u32 = 38;

fn init_main(ctx: &mut br_pem_decoder_context) {
    ctx.ip = 0;
    t0_enter(ctx, INIT_MAIN_SLOT);
}

#[inline]
fn t0_enter(ctx: &mut br_pem_decoder_context, slot: u32) {
    let mut newip = T0_CADDR[(slot - T0_INTERPRETED) as usize] as usize;
    let lnum = t0_parse7E_unsigned(&T0_CODEBLOCK, &mut newip);
    ctx.rp += lnum as usize;
    ctx.rp_stack[ctx.rp] = (ctx.ip as u32) + (lnum << 16);
    ctx.rp += 1;
    ctx.ip = newip;
}

// Stack helpers operating on the context arrays.
macro_rules! pop { ($c:expr) => {{ $c.dp -= 1; $c.dp_stack[$c.dp] }} }
macro_rules! popi { ($c:expr) => {{ $c.dp -= 1; $c.dp_stack[$c.dp] as i32 }} }
macro_rules! push { ($c:expr, $v:expr) => {{ $c.dp_stack[$c.dp] = $v; $c.dp += 1; }} }
macro_rules! pushi { ($c:expr, $v:expr) => {{ $c.dp_stack[$c.dp] = ($v as i32) as u32; $c.dp += 1; }} }
macro_rules! peek { ($c:expr, $x:expr) => {{ $c.dp_stack[$c.dp - 1 - ($x)] }} }
macro_rules! local { ($c:expr, $x:expr) => { $c.rp_stack[$c.rp - 2 - ($x as usize)] } }

/// Faithful port of `br_pem_decoder_run`. `chunk` is the current input chunk;
/// `ctx.cur_pos`/`ctx.hlen` track the read position (mirroring `hbuf`/`hlen`).
fn run(ctx: &mut br_pem_decoder_context, chunk: &[u8]) {
    let mut t0x: u32;
    loop {
        // t0_next:
        t0x = T0_CODEBLOCK[ctx.ip] as u32;
        ctx.ip += 1;
        if t0x < T0_INTERPRETED {
            match t0x {
                0 => {
                    // ret
                    ctx.rp -= 1;
                    let v = ctx.rp_stack[ctx.rp];
                    ctx.rp -= (v >> 16) as usize;
                    let v = v & 0xFFFF;
                    if v == 0 {
                        return;
                    }
                    ctx.ip = v as usize;
                }
                1 => {
                    // literal constant
                    let v = t0_parse7E_signed(&T0_CODEBLOCK, &mut ctx.ip);
                    pushi!(ctx, v);
                }
                2 => {
                    // read local
                    let x = t0_parse7E_unsigned(&T0_CODEBLOCK, &mut ctx.ip);
                    let v = local!(ctx, x);
                    push!(ctx, v);
                }
                3 => {
                    // write local
                    let x = t0_parse7E_unsigned(&T0_CODEBLOCK, &mut ctx.ip);
                    let v = pop!(ctx);
                    local!(ctx, x) = v;
                }
                4 => {
                    // jump
                    let off = t0_parse7E_signed(&T0_CODEBLOCK, &mut ctx.ip);
                    ctx.ip = (ctx.ip as i32 + off) as usize;
                }
                5 => {
                    // jump if
                    let off = t0_parse7E_signed(&T0_CODEBLOCK, &mut ctx.ip);
                    if pop!(ctx) != 0 {
                        ctx.ip = (ctx.ip as i32 + off) as usize;
                    }
                }
                6 => {
                    // jump if not
                    let off = t0_parse7E_signed(&T0_CODEBLOCK, &mut ctx.ip);
                    if pop!(ctx) == 0 {
                        ctx.ip = (ctx.ip as i32 + off) as usize;
                    }
                }
                7 => {
                    // +
                    let b = pop!(ctx);
                    let a = pop!(ctx);
                    push!(ctx, a.wrapping_add(b));
                }
                8 => {
                    // -
                    let b = pop!(ctx);
                    let a = pop!(ctx);
                    push!(ctx, a.wrapping_sub(b));
                }
                9 => {
                    // <
                    let b = popi!(ctx);
                    let a = popi!(ctx);
                    push!(ctx, (0u32).wrapping_sub((a < b) as u32));
                }
                10 => {
                    // <<
                    let c = popi!(ctx);
                    let x = pop!(ctx);
                    push!(ctx, x.wrapping_shl(c as u32));
                }
                11 => {
                    // <=
                    let b = popi!(ctx);
                    let a = popi!(ctx);
                    push!(ctx, (0u32).wrapping_sub((a <= b) as u32));
                }
                12 => {
                    // <>
                    let b = pop!(ctx);
                    let a = pop!(ctx);
                    push!(ctx, (0u32).wrapping_sub((a != b) as u32));
                }
                13 => {
                    // =
                    let b = pop!(ctx);
                    let a = pop!(ctx);
                    push!(ctx, (0u32).wrapping_sub((a == b) as u32));
                }
                14 => {
                    // >=
                    let b = popi!(ctx);
                    let a = popi!(ctx);
                    push!(ctx, (0u32).wrapping_sub((a >= b) as u32));
                }
                15 => {
                    // >>
                    let c = popi!(ctx);
                    let x = popi!(ctx);
                    pushi!(ctx, x >> c);
                }
                16 => {
                    // and
                    let b = pop!(ctx);
                    let a = pop!(ctx);
                    push!(ctx, a & b);
                }
                17 => {
                    // co
                    return;
                }
                18 => {
                    // data-get8
                    let addr = pop!(ctx) as usize;
                    push!(ctx, T0_DATABLOCK[addr] as u32);
                }
                19 => {
                    // drop
                    let _ = pop!(ctx);
                }
                20 => {
                    // dup
                    let v = peek!(ctx, 0);
                    push!(ctx, v);
                }
                21 => {
                    // flush-buf
                    if ctx.ptr > 0 {
                        if let Some(cb) = ctx.dest.as_mut() {
                            cb(&ctx.buf[..ctx.ptr]);
                        }
                        ctx.ptr = 0;
                    }
                }
                22 => {
                    // from-base64
                    let c = pop!(ctx);
                    let p = c.wrapping_sub(0x41);
                    let q = c.wrapping_sub(0x61);
                    let r = c.wrapping_sub(0x30);
                    let z = (p.wrapping_add(2) & (0u32).wrapping_sub(LT(p, 26)))
                        | (q.wrapping_add(28) & (0u32).wrapping_sub(LT(q, 26)))
                        | (r.wrapping_add(54) & (0u32).wrapping_sub(LT(r, 10)))
                        | (64 & (0u32).wrapping_sub(EQ(c, 0x2B)))
                        | (65 & (0u32).wrapping_sub(EQ(c, 0x2F)))
                        | EQ(c, 0x3D);
                    pushi!(ctx, (z as i32) - 2);
                }
                23 => {
                    // get8
                    let addr = pop!(ctx);
                    push!(ctx, ctx.get8(addr) as u32);
                }
                24 => {
                    // over
                    let v = peek!(ctx, 1);
                    push!(ctx, v);
                }
                25 => {
                    // read8-native
                    if ctx.hlen > 0 {
                        let x = chunk[ctx.cur_pos];
                        ctx.cur_pos += 1;
                        ctx.hlen -= 1;
                        push!(ctx, x as u32);
                    } else {
                        pushi!(ctx, -1);
                    }
                }
                26 => {
                    // set8
                    let addr = pop!(ctx);
                    let x = pop!(ctx);
                    ctx.set8(addr, x as u8);
                }
                27 => {
                    // swap
                    let t = ctx.dp_stack[ctx.dp - 2];
                    ctx.dp_stack[ctx.dp - 2] = ctx.dp_stack[ctx.dp - 1];
                    ctx.dp_stack[ctx.dp - 1] = t;
                }
                28 => {
                    // write8
                    let x = pop!(ctx) as u8;
                    ctx.buf[ctx.ptr] = x;
                    ctx.ptr += 1;
                    if ctx.ptr == ctx.buf.len() {
                        if let Some(cb) = ctx.dest.as_mut() {
                            cb(&ctx.buf[..]);
                        }
                        ctx.ptr = 0;
                    }
                }
                _ => unreachable!(),
            }
        } else {
            t0_enter(ctx, t0x);
        }
    }
}
