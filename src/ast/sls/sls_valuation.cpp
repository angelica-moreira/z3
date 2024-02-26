/*++
Copyright (c) 2024 Microsoft Corporation

Module Name:

    sls_valuation.cpp

Abstract:

    A Stochastic Local Search (SLS) engine
    Uses invertibility conditions, 
    interval annotations
    don't care annotations

Author:

    Nikolaj Bjorner (nbjorner) 2024-02-07
    
--*/

#include "ast/sls/sls_valuation.h"

namespace bv {

    void bvect::set_bw(unsigned bw) {
        this->bw = bw;
        nw = (bw + sizeof(digit_t) * 8 - 1) / (8 * sizeof(digit_t));
        mask = (1 << (bw % (8 * sizeof(digit_t)))) - 1;
        if (mask == 0)
            mask = ~(digit_t)0;
        reserve(nw + 1);     
    }

    bool operator==(bvect const& a, bvect const& b) {
        SASSERT(a.nw > 0);
        return 0 == mpn_manager().compare(a.data(), a.nw, b.data(), a.nw);
    }

    bool operator<(bvect const& a, bvect const& b) {
        SASSERT(a.nw > 0);       
        return mpn_manager().compare(a.data(), a.nw, b.data(), a.nw) < 0;
    }

    bool operator>(bvect const& a, bvect const& b) {
        SASSERT(a.nw > 0);
        return mpn_manager().compare(a.data(), a.nw, b.data(), a.nw) > 0;
    }

    bool operator<=(bvect const& a, bvect const& b) {
        SASSERT(a.nw > 0);
        return mpn_manager().compare(a.data(), a.nw, b.data(), a.nw) <= 0;
    }

    bool operator>=(bvect const& a, bvect const& b) {
        SASSERT(a.nw > 0);
        return mpn_manager().compare(a.data(), a.nw, b.data(), a.nw) >= 0;
    }

    std::ostream& operator<<(std::ostream& out, bvect const& v) {
        out << std::hex;
        bool nz = false;
        for (unsigned i = v.nw; i-- > 0;) {
            auto w = v[i];
            if (i + 1 == v.nw)
                w &= v.mask;
            if (nz)
                out << std::setw(8) << std::setfill('0') << w;
            else if (w != 0)
                out << w, nz = true;
        }
        if (!nz)
            out << "0";
        out << std::dec;
        return out;
    }

    sls_valuation::sls_valuation(unsigned bw) {
        set_bw(bw);
        m_lo.set_bw(bw);
        m_hi.set_bw(bw);
        m_bits.set_bw(bw);
        fixed.set_bw(bw);
        eval.set_bw(bw);
        // have lo, hi bits, fixed point to memory allocated within this of size num_bytes each allocated        
        for (unsigned i = 0; i < nw; ++i)
            m_lo[i] = 0, m_hi[i] = 0, m_bits[i] = 0, fixed[i] = 0, eval[i] = 0;
        fixed[nw - 1] = ~mask;
    }

    void sls_valuation::set_bw(unsigned b) {
        bw = b;
        nw = (bw + sizeof(digit_t) * 8 - 1) / (8 * sizeof(digit_t));
        mask = (1 << (bw % (8 * sizeof(digit_t)))) - 1;
        if (mask == 0)
            mask = ~(digit_t)0;
    }

    void sls_valuation::commit_eval() { 
        DEBUG_CODE(
            for (unsigned i = 0; i < nw; ++i)
                VERIFY(0 == (fixed[i] & (m_bits[i] ^ eval[i])));
        );
        for (unsigned i = 0; i < nw; ++i) 
            m_bits[i] = eval[i]; 
        SASSERT(well_formed()); 
    }

    bool sls_valuation::in_range(bvect const& bits) const {
        mpn_manager m;
        auto c = m.compare(m_lo.data(), nw, m_hi.data(), nw);
        SASSERT(!has_overflow(bits));
        // full range
        if (c == 0)
            return true;
        // lo < hi: then lo <= bits & bits < hi
        if (c < 0)
            return
            m.compare(m_lo.data(), nw, bits.data(), nw) <= 0 &&
            m.compare(bits.data(), nw, m_hi.data(), nw) < 0;
        // hi < lo: bits < hi or lo <= bits
        return
            m.compare(m_lo.data(), nw, bits.data(), nw) <= 0 ||
            m.compare(bits.data(), nw, m_hi.data(), nw) < 0;
    }

    //
    // largest dst <= src and dst is feasible
    // set dst := src & (~fixed | bits)
    // 
    // increment dst if dst < src by setting bits below msb(src & ~dst) to 1
    // 
    // if dst < lo < hi:
    //    return false
    // if lo < hi <= dst:
    //    set dst := hi - 1
    // if hi <= dst < lo
    //    set dst := hi - 1
    // 

    bool sls_valuation::get_at_most(bvect const& src, bvect& dst) const {
        SASSERT(!has_overflow(src));
        for (unsigned i = 0; i < nw; ++i)
            dst[i] = src[i] & (~fixed[i] | m_bits[i]);

        //
        // If dst < src, then find the most significant 
        // bit where src[idx] = 1, dst[idx] = 0
        // set dst[j] = bits_j | ~fixed_j for j < idx
        //
        for (unsigned i = nw; i-- > 0; ) {
            if (0 != (~dst[i] & src[i])) {
                auto idx = log2(~dst[i] & src[i]);
                auto mask = (1 << idx) - 1;
                dst[i] = (~fixed[i] & mask) | dst[i];
                for (unsigned j = i; j-- > 0; )
                    dst[j] = (~fixed[j] | m_bits[j]);
                break;
            }
        }
        SASSERT(!has_overflow(dst));
        return round_down(dst);
    }

    //
    // smallest dst >= src and dst is feasible with respect to this.
    // set dst := (src & ~fixed) | (fixed & bits)
    // 
    // decrement dst if dst > src by setting bits below msb to 0 unless fixed
    // 
    // if lo < hi <= dst
    //    return false
    // if dst < lo < hi:
    //    set dst := lo
    // if hi <= dst < lo
    //    set dst := lo
    // 
    bool sls_valuation::get_at_least(bvect const& src, bvect& dst) const {
        SASSERT(!has_overflow(src));
        for (unsigned i = 0; i < nw; ++i)
            dst[i] = (~fixed[i] & src[i]) | (fixed[i] & m_bits[i]);

        //
        // If dst > src, then find the most significant 
        // bit where src[idx] = 0, dst[idx] = 1
        // set dst[j] = dst[j] & fixed_j for j < idx
        //
        for (unsigned i = nw; i-- > 0; ) {
            if (0 != (dst[i] & ~src[i])) {
                auto idx = log2(dst[i] & ~src[i]);
                auto mask = (1 << idx);
                dst[i] = dst[i] & (fixed[i] | mask);
                for (unsigned j = i; j-- > 0; )
                    dst[j] = dst[j] & fixed[j];
                break;
            }
        }
        SASSERT(!has_overflow(dst));
        return round_up(dst);
    }

    bool sls_valuation::round_up(bvect& dst) const {
        if (m_lo < m_hi) {
            if (m_hi <= dst)
                return false;
            if (m_lo > dst)
                set(dst, m_lo);
        }
        else if (m_hi <= dst && m_lo > dst)
            set(dst, m_lo);
        SASSERT(!has_overflow(dst));
        return true;
    }

    bool sls_valuation::round_down(bvect& dst) const {
        if (m_lo < m_hi) {
            if (m_lo > dst)
                return false;
            if (m_hi <= dst) {
                set(dst, m_hi);
                sub1(dst);
            }
        }
        else if (m_hi <= dst && m_lo > dst) {
            set(dst, m_hi);
            sub1(dst);
        }
        SASSERT(well_formed());
        return true;
    }

    bool sls_valuation::set_random_at_most(bvect const& src, bvect& tmp, random_gen& r) {
        if (!get_at_most(src, tmp))
            return false;
        if (is_zero(tmp) || (0 == r() % 2))
            return try_set(tmp);

        set_random_below(tmp, r);
        // random value below tmp

        if (m_lo == m_hi || is_zero(m_lo) || m_lo <= tmp)
            return try_set(tmp);

        // for simplicity, bail out if we were not lucky
        return get_at_most(src, tmp) && try_set(tmp);  
    }

    bool sls_valuation::set_random_at_least(bvect const& src, bvect& tmp, random_gen& r) {
        if (!get_at_least(src, tmp))
            return false;
        if (is_ones(tmp) || (0 == r() % 2))
            return try_set(tmp);

        // random value at least tmp
        set_random_above(tmp, r);
       
        if (m_lo == m_hi || is_zero(m_hi) || m_hi > tmp)
            return try_set(tmp);

        // for simplicity, bail out if we were not lucky
        return get_at_least(src, tmp) && try_set(tmp);        
    }

    bool sls_valuation::set_random_in_range(bvect const& lo, bvect const& hi, bvect& tmp, random_gen& r) {
        if (0 == r() % 2) {
            if (!get_at_least(lo, tmp))
                return false;
            SASSERT(in_range(tmp));
            if (hi < tmp)
                return false;

            if (is_ones(tmp) || (0 == r() % 2))
                return try_set(tmp);
            set_random_above(tmp, r);
            round_down(tmp, [&](bvect const& t) { return hi >= t && in_range(t); });
            if (in_range(tmp) && lo <= tmp && hi >= tmp)
                return try_set(tmp);
            return get_at_least(lo, tmp) && hi >= tmp && try_set(tmp);
        }
        else {
            if (!get_at_most(hi, tmp))
                return false;
            SASSERT(in_range(tmp));
            if (lo > tmp)
                return false;
            if (is_zero(tmp) || (0 == r() % 2))
                return try_set(tmp);
            set_random_below(tmp, r);
            round_up(tmp, [&](bvect const& t) { return lo <= t && in_range(t); });
            if (in_range(tmp) && lo <= tmp && hi >= tmp)
                return try_set(tmp);
            return get_at_most(hi, tmp) && lo <= tmp && try_set(tmp);
        }
    }

    void sls_valuation::round_down(bvect& dst, std::function<bool(bvect const&)> const& is_feasible) {      
        for (unsigned i = bw; !is_feasible(dst) && i-- > 0; )
            if (!fixed.get(i) && dst.get(i))
                dst.set(i, false);        
    }

    void sls_valuation::round_up(bvect& dst, std::function<bool(bvect const&)> const& is_feasible) {
        for (unsigned i = 0; !is_feasible(dst) && i < bw; ++i)
            if (!fixed.get(i) && !dst.get(i))
                dst.set(i, true);
    }

    void sls_valuation::set_random_above(bvect& dst, random_gen& r) {
        for (unsigned i = 0; i < nw; ++i)
            dst[i] = dst[i] | (random_bits(r) & ~fixed[i]);
    }

    void sls_valuation::set_random_below(bvect& dst, random_gen& r) {
        if (is_zero(dst))
            return;
        unsigned n = 0, idx = UINT_MAX;
        for (unsigned i = 0; i < bw; ++i)
            if (dst.get(i) && !fixed.get(i) && (r() % ++n) == 0)
                idx = i;                

        if (idx == UINT_MAX)
            return;
        dst.set(idx, false);
        for (unsigned i = 0; i < idx; ++i) 
            if (!fixed.get(i))
                dst.set(i, r() % 2 == 0);
    }

    bool sls_valuation::set_repair(bool try_down, bvect& dst) {
        for (unsigned i = 0; i < nw; ++i)
            dst[i] = (~fixed[i] & dst[i]) | (fixed[i] & m_bits[i]);
        bool ok = try_down ? round_down(dst) : round_up(dst);
        if (!ok)
            VERIFY(try_down ? round_up(dst) : round_down(dst));
        DEBUG_CODE(SASSERT(0 == (mask & (fixed[nw-1] & (m_bits[nw-1] ^ dst[nw-1])))); for (unsigned i = 0; i + 1 < nw; ++i) SASSERT(0 == (fixed[i] & (m_bits[i] ^ dst[i]))););
        set(eval, dst);
        SASSERT(well_formed());
        return true;
    }

    void sls_valuation::min_feasible(bvect& out) const {
        if (m_lo < m_hi) {
            for (unsigned i = 0; i < nw; ++i)
                out[i] = m_lo[i];
        }
        else {
            for (unsigned i = 0; i < nw; ++i)
                out[i] = fixed[i] & m_bits[i];
        }
        SASSERT(!has_overflow(out));
    }

    void sls_valuation::max_feasible(bvect& out) const {
        if (m_lo < m_hi) {
            for (unsigned i = 0; i < nw; ++i)
                out[i] = m_hi[i];
            sub1(out);
        }
        else {
            for (unsigned i = 0; i < nw; ++i)
                out[i] = ~fixed[i] | m_bits[i];
        }
        SASSERT(!has_overflow(out));
    }

    unsigned sls_valuation::msb(bvect const& src) const {
        SASSERT(!has_overflow(src));
        for (unsigned i = nw; i-- > 0; )
            if (src[i] != 0)
                return i * 8 * sizeof(digit_t) + log2(src[i]);
        return bw;
    }

    void sls_valuation::set_value(bvect& bits, rational const& n) {
        for (unsigned i = 0; i < bw; ++i)
            bits.set(i, n.get_bit(i));
        clear_overflow_bits(bits);
    }

    rational sls_valuation::get_value(bvect const& bits) const {
        rational p(1), r(0);
        for (unsigned i = 0; i < nw; ++i) {
            r += p * rational(bits[i]);
            p *= rational::power_of_two(8 * sizeof(digit_t));
        }
        return r;
    }

    void sls_valuation::get(bvect& dst) const {
        for (unsigned i = 0; i < nw; ++i)
            dst[i] = m_bits[i];
    }

    digit_t sls_valuation::random_bits(random_gen& rand) {
        digit_t r = 0;
        for (digit_t i = 0; i < sizeof(digit_t); ++i)
            r ^= rand() << (8 * i);
        return r;
    }

    void sls_valuation::get_variant(bvect& dst, random_gen& r) const {
        for (unsigned i = 0; i < nw; ++i)
            dst[i] = (random_bits(r) & ~fixed[i]) | (fixed[i] & m_bits[i]);
        clear_overflow_bits(dst);
    }

    //
    // new_bits != bits => ~fixed
    // 0 = (new_bits ^ bits) & fixed
    // also check that new_bits are in range
    //
    bool sls_valuation::can_set(bvect const& new_bits) const {
        SASSERT(!has_overflow(new_bits));
        for (unsigned i = 0; i < nw; ++i)
            if (0 != ((new_bits[i] ^ m_bits[i]) & fixed[i]))
                return false;
        return in_range(new_bits);
    }

    unsigned sls_valuation::to_nat(unsigned max_n) {
        bvect const& d = m_bits;
        SASSERT(!has_overflow(d));
        SASSERT(max_n < UINT_MAX / 2);
        unsigned p = 1;
        unsigned value = 0;
        for (unsigned i = 0; i < bw; ++i) {
            if (p >= max_n) {
                for (unsigned j = i; j < bw; ++j)
                    if (d.get(j))
                        return max_n;
                return value;
            }
            if (d.get(i))
                value += p;
            p <<= 1;
        }
        return value;
    }

    void sls_valuation::shift_right(bvect& out, unsigned shift) const {
        SASSERT(shift < bw);
        for (unsigned i = 0; i < bw; ++i)
            out.set(i, i + shift < bw ? m_bits.get(i + shift) : false);
        SASSERT(well_formed());
    }

    void sls_valuation::add_range(rational l, rational h) {
        
        l = mod(l, rational::power_of_two(bw));
        h = mod(h, rational::power_of_two(bw));
        if (h == l)
            return;

        SASSERT(is_zero(fixed)); // ranges can only be added before fixed bits are set.

        if (m_lo == m_hi) {
            set_value(m_lo, l);
            set_value(m_hi, h);
        }
        else {            
            auto old_lo = get_value(m_lo);
            auto old_hi = get_value(m_hi);
            if (old_lo < old_hi) {
                if (old_lo < l && l < old_hi)
                    set_value(m_lo, l),
                    old_lo = l;
                if (old_hi < h && h < old_hi)
                    set_value(m_hi, h);
            }
            else {
                SASSERT(old_hi < old_lo);
                if (old_lo < l || l < old_hi)
                    set_value(m_lo, l),
                    old_lo = l;
                if (old_lo < h && h < old_hi)
                    set_value(m_hi, h);
                else if (old_hi < old_lo && (h < old_hi || old_lo < h))
                    set_value(m_hi, h);
            }
        }
        SASSERT(!has_overflow(m_lo));
        SASSERT(!has_overflow(m_hi));
        if (!in_range(eval))
            set(eval, m_lo);
        SASSERT(well_formed());
    }

    //
    // tighten lo/hi based on fixed bits.
    //   lo[bit_i] != fixedbit[bit_i] 
    //     let bit_i be most significant bit position of disagreement.
    //     if fixedbit = 1, lo = 0, increment lo
    //     if fixedbit = 0, lo = 1, lo := fixed & bits
    //   (hi-1)[bit_i] != fixedbit[bit_i]
    //     if fixedbit = 0, hi-1 = 1, set hi-1 := 0, maximize below bit_i
    //     if fixedbit = 1, hi-1 = 0, hi := fixed & bits
    // tighten fixed bits based on lo/hi
    //  lo + 1 = hi -> set bits = lo
    //  lo < hi, set most significant bits based on hi
    //
    void sls_valuation::init_fixed() {
        if (m_lo == m_hi)
            return;
        for (unsigned i = bw; i-- > 0; ) {
            if (!fixed.get(i))
                continue;
            if (m_bits.get(i) == m_lo.get(i))
                continue;
            if (m_bits.get(i)) {
                m_lo.set(i, true);
                for (unsigned j = i; j-- > 0; )
                    m_lo.set(j, fixed.get(j) && m_bits.get(j));
            }
            else {
                for (unsigned j = bw; j-- > 0; )
                    m_lo.set(j, fixed.get(j) && m_bits.get(j));
            }
            break;
        }
        bvect hi1(nw + 1);
        bvect one(nw + 1);
        one[0] = 1;
        digit_t c;
        mpn_manager().sub(m_hi.data(), nw, one.data(), nw, hi1.data(), &c);
        clear_overflow_bits(hi1);
        for (unsigned i = bw; i-- > 0; ) {
            if (!fixed.get(i))
                continue;
            if (m_bits.get(i) == hi1.get(i))
                continue;
            if (hi1.get(i)) {
                hi1.set(i, false);
                for (unsigned j = i; j-- > 0; )
                    hi1.set(j, !fixed.get(j) || m_bits.get(j));
            }
            else {
                for (unsigned j = bw; j-- > 0; )
                    hi1.set(j, fixed.get(j) && m_bits.get(j));
            }
            mpn_manager().add(hi1.data(), nw, one.data(), nw, m_hi.data(), nw + 1, &c);
            clear_overflow_bits(m_hi);
            break;
        }

        // set fixed bits based on bounds
        auto set_fixed_bit = [&](unsigned i, bool b) {
            if (!fixed.get(i)) {
                fixed.set(i, true);
                eval.set(i, b);
            }
            };

        // set most significant bits
        if (m_lo < m_hi) {
            unsigned i = bw;
            for (; i-- > 0 && !m_hi.get(i); )
                set_fixed_bit(i, false);

            if (is_power_of2(m_hi))
                set_fixed_bit(i, false);
        }

        // lo + 1 = hi: then bits = lo
        mpn_manager().add(m_lo.data(), nw, one.data(), nw, hi1.data(), nw + 1, &c);
        clear_overflow_bits(hi1);
        if (m_hi == hi1) {
            for (unsigned i = 0; i < bw; ++i)
                set_fixed_bit(i, m_lo.get(i));
        }
        SASSERT(well_formed());
    }

    void sls_valuation::set_sub(bvect& out, bvect const& a, bvect const& b) const {
        digit_t c;
        mpn_manager().sub(a.data(), nw, b.data(), nw, out.data(), &c);
        clear_overflow_bits(out);
    }

    bool sls_valuation::set_add(bvect& out, bvect const& a, bvect const& b) const {
        digit_t c;
        mpn_manager().add(a.data(), nw, b.data(), nw, out.data(), nw + 1, &c);
        bool ovfl = out[nw] != 0 || has_overflow(out);
        clear_overflow_bits(out);
        return ovfl;
    }

    bool sls_valuation::set_mul(bvect& out, bvect const& a, bvect const& b, bool check_overflow) const {
        mpn_manager().mul(a.data(), nw, b.data(), nw, out.data());
        bool ovfl = false;
        if (check_overflow) {
            ovfl = has_overflow(out);
            for (unsigned i = nw; i < 2 * nw; ++i)
                ovfl |= out[i] != 0;
        }
        clear_overflow_bits(out);
        return ovfl;
    }

    bool sls_valuation::is_power_of2(bvect const& src) const {
        unsigned c = 0;
        for (unsigned i = 0; i < nw; ++i)
            c += get_num_1bits(src[i]);
        return c == 1;
    }


}
