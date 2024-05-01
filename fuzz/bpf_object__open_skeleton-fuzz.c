#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>
#include <stddef.h>
#include <string>

// Wrap libbpf.h with extern "C"
extern "C" {
#include "./libbpf.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider stream(data, size);

  // Initialize bpf_object_skeleton
  bpf_object_skeleton obj_skeleton;
  obj_skeleton.sz = stream.ConsumeIntegral<size_t>();
  std::string name = stream.ConsumeRandomLengthString();
  obj_skeleton.name = name.c_str();
  std::vector<uint8_t> obj_data = stream.ConsumeBytes<uint8_t>(stream.ConsumeIntegralInRange(0, 100));
  obj_skeleton.data = obj_data.data();
  obj_skeleton.data_sz = obj_data.size();
  bpf_object_skeleton *obj_skel_ptr = &obj_skeleton;

  // Initialize bpf_object_open_opts
  bpf_object_open_opts open_opts;
  open_opts.sz = stream.ConsumeIntegral<size_t>();
  std::string object_name = stream.ConsumeRandomLengthString();
  open_opts.object_name = object_name.c_str();
  open_opts.relaxed_maps = stream.ConsumeBool();
  std::string pin_root_path = stream.ConsumeRandomLengthString();
  open_opts.pin_root_path = pin_root_path.c_str();
  std::string kconfig = stream.ConsumeRandomLengthString();
  open_opts.kconfig = kconfig.c_str();
  std::string btf_custom_path = stream.ConsumeRandomLengthString();
  open_opts.btf_custom_path = btf_custom_path.c_str();
  std::string kernel_log_buf = stream.ConsumeRandomLengthString();
  open_opts.kernel_log_buf = const_cast<char *>(kernel_log_buf.c_str());
  open_opts.kernel_log_size = stream.ConsumeIntegral<size_t>();
  open_opts.kernel_log_level = stream.ConsumeIntegral<__u32>();

  // Call the target function
  int result = bpf_object__open_skeleton(obj_skel_ptr, &open_opts);

  return 0;
}