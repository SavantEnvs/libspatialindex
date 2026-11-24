// Fuzz the RTree ISpatialIndex API on a memory storage manager (optionally
// behind a RandomEvictionsBuffer): insertData / deleteData and every query
// type, with coordinates taken as raw IEEE-754 doubles so NaN and +/-Inf reach
// RTree::insertData (upstream fix 494d966f rejects them there).
//
// Header: variant, dimension (2..4), index/leaf capacity (4..35), fill factor,
// buffer flag. Then records: op byte, id, 2*dim doubles, optional data blob.
#include <spatialindex/SpatialIndex.h>
#include "fuzz_common.h"

using namespace SpatialIndex;

namespace {
class Sink : public IVisitor {
 public:
  size_t n = 0;
  void visitNode(const INode& node) override { n += node.getChildrenCount(); }
  void visitData(const IData& d) override {
    uint8_t* p = nullptr; uint32_t len = 0;
    d.getData(len, &p);
    n += len;
    delete[] p;
  }
  void visitData(std::vector<const IData*>& v) override { n += v.size(); }
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzReader in(data, size);
  RTree::RTreeVariant rv = static_cast<RTree::RTreeVariant>(in.u8() % 3);
  uint32_t dim = 2 + in.u8() % 3;
  uint32_t icap = 4 + in.u8() % 32;
  uint32_t lcap = 4 + in.u8() % 32;
  double fill = 0.05 + (in.u8() % 45) / 100.0;  // initNew requires 0 < fill < 1
  bool buffered = in.u8() & 1;

  IStorageManager* mem = StorageManager::createNewMemoryStorageManager();
  IStorageManager* sm = mem;
  StorageManager::IBuffer* buf = nullptr;
  if (buffered) { buf = StorageManager::createNewRandomEvictionsBuffer(*mem, 8, false); sm = buf; }
  ISpatialIndex* tree = nullptr;
  try {
    id_type indexId;
    tree = RTree::createNewRTree(*sm, fill, icap, lcap, dim, rv, indexId);
    Sink sink;
    unsigned ops = 0;
    while (in.ok() && ops++ < 512) {
      uint8_t op = in.u8();
      id_type id = in.i64() & 0xff;  // small id space so deletes hit inserted items
      double lo[4], hi[4];
      for (uint32_t i = 0; i < dim; ++i) lo[i] = in.f64();
      for (uint32_t i = 0; i < dim; ++i) hi[i] = in.f64();
      try {
        switch (op % 10) {
          case 0: case 1: case 2: {
            Region r(lo, hi, dim);
            uint8_t blob[16];
            uint32_t blen = (op >> 4) % 17;
            in.bytes(blob, blen > 16 ? 16 : blen);
            tree->insertData(blen > 16 ? 16 : blen, blen ? blob : nullptr, r, id);
            break;
          }
          case 3: { Point p(lo, dim); tree->insertData(0, nullptr, p, id); break; }
          case 4: { Region r(lo, hi, dim); tree->deleteData(r, id); break; }
          case 5: { Region r(lo, hi, dim); tree->intersectsWithQuery(r, sink); break; }
          case 6: { Region r(lo, hi, dim); tree->containsWhatQuery(r, sink); break; }
          case 7: { Point p(lo, dim); tree->pointLocationQuery(p, sink); break; }
          case 8: { Point p(lo, dim); tree->nearestNeighborQuery(1 + (op >> 4), p, sink); break; }
          case 9: {
            if (op & 0x10) { Region r(lo, hi, dim); tree->selfJoinQuery(r, sink); }
            else { LineSegment ls(lo, hi, dim); tree->intersectsWithQuery(ls, sink); }
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
  delete buf;
  delete mem;
  return 0;
}
