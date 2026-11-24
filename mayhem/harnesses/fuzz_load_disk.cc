// Fuzz the persisted index-file loaders: StorageManager::loadDiskStorageManager
// (the .idx page map + .dat pages) followed by loadRTree / loadMVRTree /
// loadTPRTree (header + node deserialisation), then queries and one update on
// the loaded tree. Compiled once per tree type with -DSIDX_TREE=1|2|3.
//
// Input layout: u16 little-endian length L, then L bytes of <base>.idx, then the
// rest as <base>.dat. Both files are written to a per-process scratch dir and
// removed after each input, so no state is carried between inputs.
#include <spatialindex/SpatialIndex.h>
#include <cstdio>
#include <fstream>
#include <limits>
#include "fuzz_common.h"

#ifndef SIDX_TREE
#define SIDX_TREE 1
#endif

using namespace SpatialIndex;

namespace {
class CountVisitor : public IVisitor {
 public:
  size_t n = 0;
  void visitNode(const INode& node) override { n += node.getChildrenCount(); }
  void visitData(const IData& d) override {
    uint8_t* p = nullptr; uint32_t len = 0;
    d.getData(len, &p);
    n += len + static_cast<size_t>(d.getIdentifier() & 1);
    delete[] p;
    IShape* s = nullptr;
    d.getShape(&s);
    delete s;
  }
  void visitData(std::vector<const IData*>& v) override { n += v.size(); }
};

bool write_file(const std::string& path, const uint8_t* d, size_t n) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) return false;
  f.write(reinterpret_cast<const char*>(d), static_cast<std::streamsize>(n));
  return static_cast<bool>(f);
}

void exercise(ISpatialIndex* tree) {
  Tools::PropertySet props;
  tree->getIndexProperties(props);
  Tools::Variant v = props.getProperty("Dimension");
  uint32_t dim = (v.m_varType == Tools::VT_ULONG) ? v.m_val.ulVal : 2;
  if (dim < 1 || dim > 16) return;  // query shapes are built with the tree's own dimension
  double lo[16], hi[16];
  for (uint32_t i = 0; i < dim; ++i) { lo[i] = -1e9; hi[i] = 1e9; }
  CountVisitor vis;
#if SIDX_TREE == 1
  Region all(lo, hi, dim);
  tree->intersectsWithQuery(all, vis);
  Point origin(lo, dim);
  tree->nearestNeighborQuery(3, origin, vis);
  tree->internalNodesQuery(all, vis);
  for (uint32_t i = 0; i < dim; ++i) { lo[i] = 0; hi[i] = 1; }
  Region small(lo, hi, dim);
  tree->insertData(0, nullptr, small, 424242);
  tree->deleteData(small, 424242);
#elif SIDX_TREE == 2
  TimeRegion all(lo, hi, 0.0, std::numeric_limits<double>::max(), dim);
  tree->intersectsWithQuery(all, vis);
  TimeRegion slice(lo, hi, 1.0, 2.0, dim);
  tree->containsWhatQuery(slice, vis);
#else
  double v0[16] = {0};
  MovingRegion all(lo, hi, v0, v0, 0.0, 100.0, dim);
  tree->intersectsWithQuery(all, vis);
#endif
  tree->isIndexValid();
  IStatistics* st = nullptr;
  tree->getStatistics(&st);
  delete st;
}
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return 0;
  size_t idx_len = static_cast<size_t>(data[0]) | (static_cast<size_t>(data[1]) << 8);
  data += 2; size -= 2;
  if (idx_len > size) idx_len = size;

  const std::string base = fuzz_scratch_dir() + "/index";
  const std::string idxf = base + ".idx", datf = base + ".dat";
  if (!write_file(idxf, data, idx_len) || !write_file(datf, data + idx_len, size - idx_len))
    abort();

  std::string name = base;
  IStorageManager* sm = nullptr;
  ISpatialIndex* tree = nullptr;
  try {
    sm = StorageManager::loadDiskStorageManager(name);
#if SIDX_TREE == 1
    tree = RTree::loadRTree(*sm, 1);
#elif SIDX_TREE == 2
    tree = MVRTree::loadMVRTree(*sm, 1);
#else
    tree = TPRTree::loadTPRTree(*sm, 1);
#endif
    exercise(tree);
  } catch (Tools::Exception&) {
  } catch (std::exception&) {
  }
  try { delete tree; } catch (Tools::Exception&) {} catch (std::exception&) {}
  try { delete sm; } catch (Tools::Exception&) {} catch (std::exception&) {}
  unlink(idxf.c_str());
  unlink(datf.c_str());
  return 0;
}
