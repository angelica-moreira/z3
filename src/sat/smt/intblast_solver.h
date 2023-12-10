/*++
Copyright (c) 2020 Microsoft Corporation

Module Name:

    intblast_solver.h

Abstract:

    Int-blast solver.
    It assumes a full assignemnt to literals in 
    irredundant clauses. 
    It picks a satisfying Boolean assignment and 
    checks if it is feasible for bit-vectors using
    an arithmetic solver.

Author:

    Nikolaj Bjorner (nbjorner) 2023-12-10

--*/
#pragma once

#include "ast/arith_decl_plugin.h"
#include "ast/bv_decl_plugin.h"
#include "solver/solver.h"
#include "sat/smt/sat_th.h"

namespace euf {
    class solver;
}

namespace intblast {

    class solver {
        struct var_info {
            expr* dst;
            rational sz;
        };

        euf::solver& ctx;
        sat::solver& s;
        ast_manager& m;
        bv_util bv;
        arith_util a;
        scoped_ptr<::solver> m_solver;
        obj_map<expr, var_info> m_vars;
        expr_ref_vector m_trail;



        bool is_bv(sat::literal lit);
        void translate(expr_ref_vector& es);
        void sorted_subterms(expr_ref_vector const& es, ptr_vector<expr>& sorted);

    public:
        solver(euf::solver& ctx);
        
        lbool check();

        rational get_value(expr* e) const;
    };

}
