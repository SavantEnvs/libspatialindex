// Fuzz the C API (sidx_api.h): bulk-load an index through Index_CreateWithStream
// (STR bulk loader + external sorter) or Index_CreateWithArray, then run
// inserts, deletes and the _obj/_id/_count/nearest-neighbour/bounds/leaves
// queries, freeing every result the way the API documents.
//
// Header bytes pick variant, dimension (2..4), capacities, fill factor, buffer
// capacity, result-set limit/offset and the creation route. The remaining bytes
// are records (id, 2*dim raw doubles, small data blob) for the stream, followed
// by an op stream once the stream callback stops.
#include <spatialindex/capi/sidx_api.h>
#include "fuzz_common.h"

namespace {
// Stream state for the readNext callback; reset at the start of every input.
FuzzReader* g_in = nullptr;
uint32_t g_dim = 2;
unsigned g_left = 0;
double g_min[4], g_max[4];
uint8_t g_blob[8];

int read_next(int64_t* id, double** pMin, double** pMax, uint32_t* nDim,
              const uint8_t** pData, size_t* nLen) {
  if (g_left == 0 || !g_in->ok()) return 1;
  --g_left;
  *id = g_in->i64();
  for (uint32_t i = 0; i < g_dim; ++i) g_min[i] = g_in->f64();
  for (uint32_t i = 0; i < g_dim; ++i) g_max[i] = g_in->f64();
  uint8_t blen = g_in->u8() % 9;
  g_in->bytes(g_blob, blen);
  *pMin = g_min; *pMax = g_max; *nDim = g_dim;
  *pData = g_blob; *nLen = blen;
  return 0;
}

void free_items(IndexItemH* items, uint64_t n) {
  for (uint64_t i = 0; i < n; ++i) {
    uint8_t* d = nullptr; uint64_t len = 0;
    if (IndexItem_GetData(items[i], &d, &len) == RT_None) Index_Free(d);
    double *mn = nullptr, *mx = nullptr; uint32_t dim = 0;
    if (IndexItem_GetBounds(items[i], &mn, &mx, &dim) == RT_None) { Index_Free(mn); Index_Free(mx); }
    (void)IndexItem_GetID(items[i]);
  }
  if (items) Index_DestroyObjResults(items, static_cast<uint32_t>(n));
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Error_Reset();
  FuzzReader in(data, size);
  g_in = &in;
  uint8_t h0 = in.u8();
  g_dim = 2 + in.u8() % 3;
  IndexPropertyH props = IndexProperty_Create();
  IndexProperty_SetIndexType(props, RT_RTree);
  IndexProperty_SetIndexStorage(props, RT_Memory);
  IndexProperty_SetDimension(props, g_dim);
  IndexProperty_SetIndexVariant(props, static_cast<RTIndexVariant>(h0 % 3));
  IndexProperty_SetIndexCapacity(props, 4 + in.u8() % 32);
  IndexProperty_SetLeafCapacity(props, 4 + in.u8() % 32);
  IndexProperty_SetFillFactor(props, 0.05 + (in.u8() % 45) / 100.0);
  IndexProperty_SetBufferingCapacity(props, 1 + in.u8() % 16);
  IndexProperty_SetResultSetLimit(props, in.u8() % 8);
  int64_t offset = in.u8() % 4;
  g_left = in.u8() % 64;

  IndexH idx = nullptr;
  if (h0 & 0x80) {
    // Array route: the same record shape, packed as id/min/max arrays.
    uint64_t n = g_left;
    int64_t ids[64];
    double mins[64 * 4], maxs[64 * 4];
    for (uint64_t i = 0; i < n; ++i) {
      ids[i] = in.i64();
      for (uint32_t d = 0; d < g_dim; ++d) mins[i * g_dim + d] = in.f64();
      for (uint32_t d = 0; d < g_dim; ++d) maxs[i * g_dim + d] = in.f64();
    }
    idx = Index_CreateWithArray(props, n, g_dim, 1, g_dim, 1, ids, mins, maxs);
  } else if (g_left) {
    idx = Index_CreateWithStream(props, read_next);
  } else {
    idx = Index_Create(props);
  }
  IndexProperty_Destroy(props);
  if (idx == nullptr) { Error_Reset(); g_in = nullptr; return 0; }
  Index_SetResultSetOffset(idx, offset);

  unsigned ops = 0;
  while (in.ok() && ops++ < 256) {
    uint8_t op = in.u8();
    int64_t id = in.u8();
    double mn[4], mx[4];
    for (uint32_t i = 0; i < g_dim; ++i) mn[i] = in.f64();
    for (uint32_t i = 0; i < g_dim; ++i) mx[i] = in.f64();
    uint64_t n = 0;
    switch (op % 9) {
      case 0: case 1: {
        uint8_t blob[8]; uint8_t blen = (op >> 4) % 9;
        in.bytes(blob, blen);
        Index_InsertData(idx, id, mn, mx, g_dim, blob, blen);
        break;
      }
      case 2: Index_DeleteData(idx, id, mn, mx, g_dim); break;
      case 3: {
        IndexItemH* items = nullptr;
        if (Index_Intersects_obj(idx, mn, mx, g_dim, &items, &n) == RT_None) free_items(items, n);
        break;
      }
      case 4: {
        int64_t* ids = nullptr;
        if ((op & 0x10 ? Index_Contains_id(idx, mn, mx, g_dim, &ids, &n)
                       : Index_Intersects_id(idx, mn, mx, g_dim, &ids, &n)) == RT_None)
          Index_Free(ids);
        break;
      }
      case 5:
        if (op & 0x10) Index_Intersects_count(idx, mn, mx, g_dim, &n);
        else Index_Contains_count(idx, mn, mx, g_dim, &n);
        break;
      case 6: {
        IndexItemH* items = nullptr;
        n = 1 + (op >> 5);  // in: k, out: result count
        if (Index_NearestNeighbors_obj(idx, mn, mx, g_dim, &items, &n) == RT_None) free_items(items, n);
        break;
      }
      case 7: {
        double *bmin = nullptr, *bmax = nullptr; uint32_t bd = 0;
        if (Index_GetBounds(idx, &bmin, &bmax, &bd) == RT_None) { Index_Free(bmin); Index_Free(bmax); }
        break;
      }
      case 8: {
        uint32_t nLeaves = 0, ld = 0;
        uint32_t* sizes = nullptr; int64_t* leafIds = nullptr; int64_t** childIds = nullptr;
        double **lmin = nullptr, **lmax = nullptr;
        if (Index_GetLeaves(idx, &nLeaves, &sizes, &leafIds, &childIds, &lmin, &lmax, &ld) == RT_None) {
          for (uint32_t i = 0; i < nLeaves; ++i) { Index_Free(childIds[i]); Index_Free(lmin[i]); Index_Free(lmax[i]); }
          Index_Free(sizes); Index_Free(leafIds); Index_Free(childIds); Index_Free(lmin); Index_Free(lmax);
        }
        break;
      }
    }
    Error_Reset();
  }
  Index_IsValid(idx);
  Index_Destroy(idx);
  Error_Reset();
  g_in = nullptr;
  return 0;
}
