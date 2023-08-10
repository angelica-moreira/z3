/*++
Copyright (c) 2020 Microsoft Corporation

Module Name:

    synth_solver.h

Author:

    Petra Hozzova 2023-08-08
    Nikolaj Bjorner (nbjorner) 2020-08-17

--*/

#pragma once

#include "sat/smt/sat_th.h"
#include "solver/solver.h"


namespace synth {

    class solver : public euf::th_euf_solver {
    public:
        solver(euf::solver& ctx);
        ~solver() override;        
        void asserted(sat::literal lit) override {}
        sat::check_result check() override;
        void push_core() override {}
        void pop_core(unsigned n) override {}
        bool unit_propagate() override;
        void get_antecedents(sat::literal l, sat::ext_justification_idx idx, sat::literal_vector & r, bool probing) override {}
        void collect_statistics(statistics& st) const override {}
        sat::literal internalize(expr* e, bool sign, bool root) override;
        void internalize(expr* e) override;
        std::ostream& display(std::ostream& out) const override;
        std::ostream& display_justification(std::ostream& out, sat::ext_justification_idx idx) const override { return out << "synth"; }
        std::ostream& display_constraint(std::ostream& out, sat::ext_constraint_idx idx) const override { return out << "synth"; }
        euf::th_solver* clone(euf::solver& ctx) override;

    private:
        sat::literal synthesize(app* e);
	void add_uncomputable(app* e);
        void add_synth_objective(app* e);
	void add_specification(app* e);
	bool contains_uncomputable(expr* e);

        void on_merge_eh(euf::enode* root, euf::enode* other);

        expr_ref compute_solution(app* synth_objective);
        bool_vector m_is_computable;
        unsigned    m_blockers_qhead = 0;
        sat::literal_vector m_blockers;

    	ptr_vector<app> m_synth;
        typedef obj_hashtable<func_decl> func_decl_set;
	func_decl_set m_uncomputable;
	typedef obj_hashtable<app> app_set;
	app_set m_spec;

    };

};
