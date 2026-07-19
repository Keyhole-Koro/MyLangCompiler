#include <assert.h>

#include "mylang/semantic/semantic.h"

/* This file is linked into the existing white-box test binary. The constructor
 * verifies the profile API without introducing a second test main(). */
__attribute__((constructor))
static void test_semantic_safety_profile_round_trip(void) {
    semantic_set_safety_profile(SEMANTIC_SAFETY_DEFAULT);
    assert(semantic_get_safety_profile() == SEMANTIC_SAFETY_DEFAULT);

    semantic_set_safety_profile(SEMANTIC_SAFETY_STRICT);
    assert(semantic_get_safety_profile() == SEMANTIC_SAFETY_STRICT);

    /* Leave global state at the default so later white-box tests are isolated. */
    semantic_set_safety_profile(SEMANTIC_SAFETY_DEFAULT);
    assert(semantic_get_safety_profile() == SEMANTIC_SAFETY_DEFAULT);
}
