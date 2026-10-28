# Browser-mode force close on testnet: results

**Status: IN PROGRESS (interim).** This file is updated as the run advances.

## Run 2 (current)
- User address: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqg22vmtld8wes25fqzs47quflp4p9h94lcu3tfnw`
- Channel `0xe4a53652834ab050ad309524a2114847658fab951942b5892f0f70a35273c9c9`, funding `0x68f0f30eaa898329c619c76b799bd6129f58757a497e96882f9e2eee3de73be7:0` (750 CKB funding cell)
- Force close requested 01:33:36 UTC (2026-10-28); commitment `0xfa3427cd841e6881b3f5f604cfb573a7b1e31c7fece5256a684c3e8c94308802` committed 01:34:03 UTC

Note: the testnet explorer API (which the test uses to follow spends) did not mark the funding cell as spent even
20+ minutes after the commitment was committed, so the chain is also tracked independently with CKB RPC
(`get_live_cell` + indexer `get_transactions`) on the same transactions.

### Test output lines
```
01:33:35 PASS browser channel 0xe4a53652834ab050ad309524a2114847658fab951942b5892f0f70a35273c9c9 ready; funding 0x68f0f30eaa898329c619c76b799bd6129f58757a497e96882f9e2eee3de73be7:0
01:33:36 PASS force close requested: ok
```

## Run 1 (aborted by a container restart)
- User address: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqtph27mpg6jn8nmagw4y6laaxr4zzg7pusp2uevy`
- Funding `0xe6a6ce2cc009be7e76f1eee868bd4ec83077a8127de40d44447454ea7dfbd04b:0` (the node's first broadcast of it was rejected with lock error -11 on Inputs[1], then it went through)
- Commitment `0xd214fbce6821292f56df8ec1969eb9761e265206b40b3b15a8c0e380efce5b9a` committed 00:40:23 UTC
- The test process and its headless browser (the Fiber node) were killed by an environment restart at ~01:28 UTC,
  so the node-side claim/sweep for this channel could not happen; the peer can still claim its share.
```
00:40:17 PASS browser channel 0xd6f4acde825940f65d8b178f7365b95c9643d1e6292a834706d4cf899643725b ready; funding 0xe6a6ce2cc009be7e76f1eee868bd4ec83077a8127de40d44447454ea7dfbd04b:0
00:40:18 PASS force close requested: ok
```
