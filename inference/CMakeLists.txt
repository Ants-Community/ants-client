# inference/ layer
#
# The canonical kernel library and the inference orchestration.
# ~10–18 engineer-months total per IMPLEMENTATION.md.
# kernels/ depends only on foundation/.
# orchestration/ depends on kernels/, embedding/, crdt/, identity/, cache/.

# Component #12 — ants-canonical-kernels  (6–12 EM CPU; +6–18 EM per GPU)
add_subdirectory(kernels)

# Component #13 — Inference orchestration  (4 EM)
add_subdirectory(orchestration)
