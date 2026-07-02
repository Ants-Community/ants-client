/*
 * cmd/antsd/run.h — `antsd run`, the node daemon's event loop.
 */
#ifndef ANTSD_RUN_H
#define ANTSD_RUN_H

/* Load the config at `path`, stand the QUIC transport up from it, and
 * drive the single-threaded tick loop until SIGINT/SIGTERM. Returns the
 * process exit code: 0 on clean shutdown, 1 on any startup failure. */
int antsd_cmd_run(const char *path);

#endif /* ANTSD_RUN_H */
