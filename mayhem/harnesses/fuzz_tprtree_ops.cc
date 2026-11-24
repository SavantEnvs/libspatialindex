// Fuzz the TPRTree (time-parameterised R-tree) ISpatialIndex API on a memory
// storage manager: insertData / deleteData with MovingRegion shapes and
// moving-region queries, which drive the MovingRegion/MovingPoint geometry.
// Coordinates and velocities are raw doubles (NaN/Inf allowed). The harness keeps two
// preconditions of the MovingRegion/TPRTree API that a real caller always meets:
//  - regions are never shrinking (vlow <= vhigh in every dimension; MovingRegion.cc asserts
//    isShrinking() == false), so each velocity pair is ordered;
//  - times are finite and advance with the op stream (t = now + step, tend > t), as the
//    TPR-tree's "current time" model requires (TPRTree.cc insertData_impl asserts
//    m_currentTime <= startTime, and MovingRegion asserts m_startTime < m_endTime).
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
  uint32_t dim = 2 + in.u8() % 3;
  uint32_t icap = 4 + in.u8() % 32;
  uint32_t lcap = 4 + in.u8() % 32;
  double fill = 0.05 + (in.u8() % 45) / 100.0;
  double horizon = 1 + in.u8();

  IStorageManager* sm = StorageManager::createNewMemoryStorageManager();
  ISpatialIndex* tree = nullptr;
  try {
    id_type indexId;
    tree = TPRTree::createNewTPRTree(*sm, fill, icap, lcap, dim, TPRTree::TPRV_RSTAR, horizon, indexId);
    Sink sink;
    double now = 0.0;
    unsigned ops = 0;
    while (in.ok() && ops++ < 512) {
      uint8_t op = in.u8();
      id_type id = in.u8();
      uint8_t step = in.u8();
      double lo[4], hi[4], vlo[4], vhi[4];
      for (uint32_t i = 0; i < dim; ++i) lo[i] = in.f64();
      for (uint32_t i = 0; i < dim; ++i) hi[i] = in.f64();
      for (uint32_t i = 0; i < dim; ++i) vlo[i] = in.f64();
      for (uint32_t i = 0; i < dim; ++i) vhi[i] = in.f64();
      for (uint32_t i = 0; i < dim; ++i)
        if (vhi[i] < vlo[i]) { double x = vlo[i]; vlo[i] = vhi[i]; vhi[i] = x; }
      // now <= 512 * (255 + 16), so t and tend are small exact integers and tend > t.
      double t = now + step;
      now = t;
      double tend = t + 1 + (op >> 4);
      try {
        switch (op % 5) {
          case 0: case 1: {
            MovingRegion r(lo, hi, vlo, vhi, t, tend, dim);
            tree->insertData(0, nullptr, r, id);
            break;
          }
          case 2: {
            // deleteData moves the tree's current time to tend; keep the stream's clock with it.
            MovingRegion r(lo, hi, vlo, vhi, t, tend, dim);
            now = tend;
            tree->deleteData(r, id);
            break;
          }
          case 3: { MovingRegion r(lo, hi, vlo, vhi, t, tend, dim); tree->intersectsWithQuery(r, sink); break; }
          case 4: { MovingRegion r(lo, hi, vlo, vhi, t, tend, dim); tree->containsWhatQuery(r, sink); break; }
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
