# Browser-mode force close on testnet: results

**Result: NOT DONE.** The test did not reach `DONE` within the 12-hour watch window (2026-10-28, all times UTC).
The force close and the peer's settlement both went through on-chain. The browser node never claimed the user's
500 CKB share: it was still unclaimed about 3 hours after it became spendable, and the fee reserve was still unspent.

## Run 2 (the reported run)
- User address: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqg22vmtld8wes25fqzs47quflp4p9h94lcu3tfnw`
- Channel `0xe4a53652834ab050ad309524a2114847658fab951942b5892f0f70a35273c9c9`, 750 CKB funding cell
  `0x68f0f30eaa898329c619c76b799bd6129f58757a497e96882f9e2eee3de73be7:0` (500 CKB user + 250 CKB peer)
- Fee reserve: `0x158925a80bfd09dc93b99bf12a016f4e43b1ef6369f612fec93dea513ed2d710:0`, 62 CKB to the node's settlement key

### Chain from the force close
| Step | Tx | Confirmed | Time since previous step |
|---|---|---|---|
| Force close requested | n/a | 01:33:36 | n/a |
| Commitment (spends funding) | `0xfa3427cd841e6881b3f5f604cfb573a7b1e31c7fece5256a684c3e8c94308802` | 01:34:03 | ~30 s |
| Peer's settlement (spends commitment) | `0x32ebef7c483c6a8370e80393e5dc4a46bc667a73d27dd764e22b6206055290f1` | 05:32:21 | 3 h 58 min (1-epoch delay, `since` `0xa000010000000001`) |
| Node's claim of the user's share (`0x32ebef7c…:0`, 499.99999544 CKB, commitment lock, same 1-epoch delay) | **not seen** | n/a | spendable from about 09:30 (epoch 14087 + 828/1800); still live at 12:35 |
| SDK sweep to the user's address | **not seen** | n/a | n/a |

The peer's settlement paid 555.55534233 CKB to the peer's own address `ckt1qzda0cr08m85…sjtcnx4` and left
499.99999544 CKB (the user's share) in a commitment-lock cell for the node to claim. At 12:35 that cell and the
62 CKB reserve cell were both live, the testnet mempool was empty, and the node had logged nothing since the close.
The test was still running at that point (`fiber running`). Its own deadline is about 13:33. So the node either
never attempted the claim or failed without logging an error the test captures; the test only forwards console
lines that match `clos|send tx|commitment|watchtower|settle|sweep|ERROR`.

To follow it later: the user's share is at `0x32ebef7c483c6a8370e80393e5dc4a46bc667a73d27dd764e22b6206055290f1:0`.

### Test output lines
```
01:33:35 PASS browser channel 0xe4a53652834ab050ad309524a2114847658fab951942b5892f0f70a35273c9c9 ready; funding 0x68f0f30eaa898329c619c76b799bd6129f58757a497e96882f9e2eee3de73be7:0
01:33:36 PASS force close requested: ok
02:03:39 PASS commitment on-chain: 0xfa3427cd841e6881b3f5f604cfb573a7b1e31c7fece5256a684c3e8c94308802
05:39:00 PASS step 1: 0xfa3427cd84… spent by 0x32ebef7c483c6a8370e80393e5dc4a46bc667a73d27dd764e22b6206055290f1: ckt1qp6qmm5rlp7x7v… 499.99999544 CKB; ckt1qzda0cr08m85hc… 555.55534233 CKB
```
(There was no DONE/TIMEOUT/page-errors line yet when this was written; the process was still waiting.)

### Notes
- The testnet explorer API, which the test uses to follow spends, lagged by about 30 minutes: the commitment was
  committed at 01:34 and the test saw it at 02:03. The timings above come from block timestamps via CKB RPC.

## Run 1 (stopped by a container restart)
- User address: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqtph27mpg6jn8nmagw4y6laaxr4zzg7pusp2uevy`
- Funding `0xe6a6ce2cc009be7e76f1eee868bd4ec83077a8127de40d44447454ea7dfbd04b:0`. The node's first broadcast of it
  was rejected with lock error -11 on Inputs[1]; a retry was accepted.
- Commitment `0xd214fbce6821292f56df8ec1969eb9761e265206b40b3b15a8c0e380efce5b9a` committed 00:40:23.
- The test process and its headless browser (the Fiber node) were killed by an environment restart at about 01:28,
  so this channel's node-side claim and sweep could not happen.
```
00:40:17 PASS browser channel 0xd6f4acde825940f65d8b178f7365b95c9643d1e6292a834706d4cf899643725b ready; funding 0xe6a6ce2cc009be7e76f1eee868bd4ec83077a8127de40d44447454ea7dfbd04b:0
00:40:18 PASS force close requested: ok
```
