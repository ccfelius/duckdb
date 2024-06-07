/* Copyright 2013 Google Inc. All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/

/* Functions to estimate the bit cost of Huffman trees. */

#include "bit_cost.h"

#include <brotli/types.h>

#include "../common/brotli_constants.h"
#include "../common/brotli_platform.h"
#include "fast_log.h"
#include "histogram.h"

using namespace duckdb_brotli;

#define FN(X) duckdb_brotli:: X ## Literal
#include "bit_cost_inc.h"  /* NOLINT(build/include) */
#undef FN

#define FN(X) duckdb_brotli:: X ## Command
#include "bit_cost_inc.h"  /* NOLINT(build/include) */
#undef FN

#define FN(X) duckdb_brotli:: X ## Distance
#include "bit_cost_inc.h"  /* NOLINT(build/include) */
#undef FN


