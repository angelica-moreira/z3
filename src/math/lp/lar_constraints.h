/*++
Copyright (c) 2017 Microsoft Corporation

Module Name:

    <name>

Abstract:

    <abstract>

Author:

    Lev Nachmanson (levnach)

Revision History:


--*/

#pragma once
#include <utility>
#include <string>
#include <algorithm>

#include "util/vector.h"
#include "util/region.h"
#include "math/lp/lp_utils.h"
#include "math/lp/ul_pair.h"
#include "math/lp/lar_term.h"
#include "math/lp/column_namer.h"
#include "math/lp/stacked_value.h"
namespace lp {
inline lconstraint_kind flip_kind(lconstraint_kind t) {
    return static_cast<lconstraint_kind>( - static_cast<int>(t));
}

inline std::string lconstraint_kind_string(lconstraint_kind t) {
    switch (t) {
    case LE: return std::string("<=");
    case LT: return std::string("<");
    case GE: return std::string(">=");
    case GT: return std::string(">");
    case EQ: return std::string("=");
    case NE: return std::string("!=");
    }
    lp_unreachable();
    return std::string(); // it is unreachable
}

struct lar_base_constraint {
    lconstraint_kind m_kind;
    mpq m_right_side;
    virtual vector<std::pair<mpq, var_index>> coeffs() const = 0;
    lar_base_constraint() {}
    lar_base_constraint(lconstraint_kind kind, const mpq& right_side) :m_kind(kind), m_right_side(right_side) {}

    virtual unsigned size() const = 0;
    virtual ~lar_base_constraint(){}
    virtual mpq get_free_coeff_of_left_side() const { return zero_of_type<mpq>();}
};

class lar_var_constraint: public lar_base_constraint {
    unsigned m_j;
public:
    vector<std::pair<mpq, var_index>> coeffs() const override {
        vector<std::pair<mpq, var_index>> ret;
        ret.push_back(std::make_pair(one_of_type<mpq>(), m_j));
        return ret;
    }
    unsigned size() const override { return 1;}
    lar_var_constraint(unsigned j, lconstraint_kind kind, const mpq& right_side) : lar_base_constraint(kind, right_side), m_j(j) { }
};


class lar_term_constraint: public lar_base_constraint {
    const lar_term * m_term;
public:
    vector<std::pair<mpq, var_index>> coeffs() const override { return m_term->coeffs_as_vector(); }
    unsigned size() const override { return m_term->size();}
    lar_term_constraint(const lar_term *t, lconstraint_kind kind, const mpq& right_side) : lar_base_constraint(kind, right_side), m_term(t) { }
};


class constraint_set {
    region                         m_region;
    column_namer&                  m_namer;
    vector<lar_base_constraint*>   m_constraints;
    stacked_value<unsigned>        m_constraint_count;

    constraint_index add(lar_base_constraint* c) {
        constraint_index ci = m_constraints.size();
        m_constraints.push_back(c);
        return ci;
    }

    std::ostream& print_left_side_of_constraint(const lar_base_constraint & c, std::ostream & out) const {
        m_namer.print_linear_combination_of_column_indices(c.coeffs(), out);
        mpq free_coeff = c.get_free_coeff_of_left_side();
        if (!is_zero(free_coeff))
            out << " + " << free_coeff;
        return out;
    }

    std::ostream& print_left_side_of_constraint_indices_only(const lar_base_constraint & c, std::ostream & out) const {
        print_linear_combination_of_column_indices_only(c.coeffs(), out);
        mpq free_coeff = c.get_free_coeff_of_left_side();
        if (!is_zero(free_coeff))
            out << " + " << free_coeff;
        return out;
    }

    std::ostream& print_left_side_of_constraint(const lar_base_constraint & c, std::function<std::string (unsigned)>& var_str, std::ostream & out) const {
        print_linear_combination_customized(c.coeffs(), var_str, out);
        mpq free_coeff = c.get_free_coeff_of_left_side();
        if (!is_zero(free_coeff))
            out << " + " << free_coeff;
        return out;
    }

    std::ostream& out_of_bounds(std::ostream& out, constraint_index ci) const {
        return out << "constraint " << T_to_string(ci) << " is not found" << std::endl;
    }

public:
    constraint_set(column_namer& cn): 
        m_namer(cn) {}

    ~constraint_set() {
        for (auto* c : m_constraints) 
            c->~lar_base_constraint();
    }

    void push() {
        m_constraint_count = m_constraints.size();
        m_constraint_count.push();
        m_region.push_scope();
    }

    void pop(unsigned k) {
        m_constraint_count.pop(k);
        for (unsigned i = m_constraints.size(); i-- > m_constraint_count; )
            m_constraints[i]->~lar_base_constraint();        
        m_constraints.shrink(m_constraint_count);
        m_region.pop_scope(k);
    }

    constraint_index add_var_constraint(var_index j, lconstraint_kind k, mpq const& rhs) {
        return add(new (m_region) lar_var_constraint(j, k, rhs));
    }

    constraint_index add_term_constraint(const lar_term* t, lconstraint_kind k, mpq const& rhs) {
        return add(new (m_region) lar_term_constraint(t, k, rhs));
    }

    lar_base_constraint const& operator[](constraint_index ci) const { return *m_constraints[ci]; }    

    // TBD: would like to make this opaque
    // and expose just active constraints
    // constraints need not be active.
    bool valid_index(constraint_index ci) const { return ci < m_constraints.size(); }
//    unsigned size() const { return m_constraints.size(); }
    vector<lar_base_constraint*>::const_iterator begin() const { return m_constraints.begin(); }
    vector<lar_base_constraint*>::const_iterator end() const { return m_constraints.end(); }

    std::ostream& display(std::ostream& out) const {
        out << "number of constraints = " << m_constraints.size() << std::endl;
        for (auto const* c : *this) {
            display(out, *c);
        }
        return out;
    }

    std::ostream& display(std::ostream& out, constraint_index ci) const {
        return (ci >= m_constraints.size()) ? out_of_bounds(out, ci) : display(out, (*this)[ci]);
    }

    std::ostream& display(std::ostream& out, lar_base_constraint const& c) const {
        print_left_side_of_constraint(c, out);
        return out << " " << lconstraint_kind_string(c.m_kind) << " " << c.m_right_side << std::endl;
    }

    std::ostream& display_indices_only(std::ostream& out, constraint_index ci) const {
        return (ci >= m_constraints.size()) ? out_of_bounds(out, ci) : display_indices_only(out, (*this)[ci]);
    }

    std::ostream& display_indices_only(std::ostream& out, lar_base_constraint const& c) const {
        print_left_side_of_constraint_indices_only(c, out);
        return out << " " << lconstraint_kind_string(c.m_kind) << " " << c.m_right_side << std::endl;
    }

    std::ostream& display(std::ostream& out, std::function<std::string (unsigned)> var_str, constraint_index ci) const {
        return (ci >= m_constraints.size()) ? out_of_bounds(out, ci) : display(out, var_str, (*this)[ci]);
    }

    std::ostream& display(std::ostream& out, std::function<std::string (unsigned)>& var_str, lar_base_constraint const& c) const {
        print_left_side_of_constraint(c, var_str, out); 
        return out << " " << lconstraint_kind_string(c.m_kind) << " " << c.m_right_side << std::endl;
    }

    
    
};

inline std::ostream& operator<<(std::ostream& out, constraint_set const& cs) { 
    return cs.display(out); 
}

}
