/*
 * cmd/antsd/ask.h — `antsd ask`: one inference request to a node.
 */
#ifndef ANTSD_ASK_H
#define ANTSD_ASK_H

/* Dial `addr` pinned to the peer-id `peer_hex` with a throwaway identity,
 * send one INFER_REQ (RFC-0008 §11.14) carrying `prompt` at `tier`, check
 * the answer and print the verdict. Returns the process exit code: 0 when
 * the answer checked out (answered), 1 for any other verdict or failure,
 * 2 on bad arguments. */
int antsd_cmd_ask(const char *addr, const char *peer_hex, const char *prompt, unsigned tier);

#endif /* ANTSD_ASK_H */
