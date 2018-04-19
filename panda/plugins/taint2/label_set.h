/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

#ifndef LABEL_SET_H
#define LABEL_SET_H

#include <cstdint>
#include <set>

typedef const std::set<uint32_t> *LabelSetP;

LabelSetP label_set_union(LabelSetP ls1, LabelSetP ls2);
LabelSetP label_set_singleton(uint32_t label);
void label_set_iter(LabelSetP ls, void (*leaf)(uint32_t, void *), void *user);
std::set<uint32_t> label_set_render_set(LabelSetP ls);

#endif
