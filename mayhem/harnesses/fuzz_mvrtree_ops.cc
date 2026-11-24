// Fuzz the MVRTree (multi-version R-tree) ISpatialIndex API on a memory storage
// manager: insertData / deleteData with TimeRegion shapes and time-interval
// queries. Coordinates are raw doubles (NaN/Inf allowed). Insert/delete times
// advance by a fuzzed step so most operations satisfy the "non-decreasing time"
// precondition of MVRTree::insertData; the library itself throws otherwise.
#include <spatialindex/SpatialIndex.h>
#include "fuzz_common.h"

using namespace SpatialIndex;

namespace {
class Sink : public IVisitor {
 public:
  size_t n = 0;
  void visitNode(const INode& node) override { n += node.getChildrenCount(); }
  void visitData(const IData& d) override { n += static_cast<size_t>(d.getIdentifier()); }
  void visitData(std::vector<const IData*>& v) override { n += v.size(); }
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzReader in(data, size);
  MVRTree::MVRTreeVariant rv = static_cast<MVRTree::MVRTreeVariant>(in.u8() % 3);
  uint32_t dim = 2 + in.u8() % 3;
  uint32_t icap = 10 + in.u8() % 24;  // MVRTree::initNew: capacities >= 10
  uint32_t lcap = 10 + in.u8() % 24;
  double fill = 0.05 + (in.u8() % 45) / 100.0;

  IStorageManager* sm = StorageManager::createNewMemoryStorageManager();
  ISpatialIndex* tree = nullptr;
  try {
    id_type indexId;
    tree = MVRTree::createNewMVRTree(*sm, fill, icap, lcap, dim, rv, indexId);
    Sink sink;
    double now = 0.0;
    unsigned ops = 0;
    while (in.ok() && ops++ < 512) {
      uint8_t op = in.u8();
      id_type id = in.u8();
      uint8_t step = in.u8();
      double lo[4], hi[4];
      for (uint32_t i = 0; i < dim; ++i) lo[i] = in.f64();
      for (uint32_t i = 0; i < dim; ++i) hi[i] = in.f64();
      // step 0xff: a raw fuzzed time (may go backwards, exercising the checks).
      double t = (step == 0xff) ? in.f64() : now + step;
      if (step != 0xff) now = t;
      try {
        switch (op % 6) {
          case 0: case 1: {
            TimeRegion r(lo, hi, t, t, dim);
            uint8_t blob[8];
            in.bytes(blob, 8);
            tree->insertData((op >> 4) % 9, blob, r, id);
            break;
          }
          case 2: { TimeRegion r(lo, hi, t, t, dim); tree->deleteData(r, id); break; }
          case 3: {
            TimeRegion r(lo, hi, t - (op >> 3), t, dim);
            tree->intersectsWithQuery(r, sink);
            break;
          }
          case 4: { TimeRegion r(lo, hi, 0, t, dim); tree->containsWhatQuery(r, sink); break; }
          case 5: {
            TimePoint p(lo, t, t, dim);
            if (op & 0x10) tree->pointLocationQuery(p, sink);
            else tree->nearestNeighborQuery(1 + (op >> 5), p, sink);
            break;
          }
        }
      } catch (Tools::Exception&) {
      }
    }
    tree->isIndexValid();
  } catch (Tools::Exception&) {
  }
  delete tree;
  delete sm;
  return 0;
}
