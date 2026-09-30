---
title: Benchmarks
date: 2025-07-05
weight: 3
---

This page documents the results of some of our benchmark suite on different hardware.  All of our code runs _single threaded_ for deployment purposes. It is important not to consume a user's battery.

## Mac M4

### FFT
Because Longfellow uses the Ligero proof system as a component, the FFT may be a bottleneck (without other measures). This benchmark measures the FFT time over different fields. Note that we have another, more realistic _interpolation_ benchmark that measures the Reed-Solomon encoding time. However, this benchmark provides a good method to compare against other implementations.  The Fp2 field is the quadratic extension over the P256 prime.  The Fp128 and Fp64 fields are prime fields of size 128- and 64- bits respectively, and the Fp64_2 field is the quadratic extension of the later.

```
---------------------------------------------------------------
Benchmark                     Time             CPU   Iterations
---------------------------------------------------------------
BM_FFT_Fp256_2/1024        170279 ns       170237 ns         4108
BM_FFT_Fp256_2/4096        847506 ns       847413 ns          825
BM_FFT_Fp256_2/16384      4026932 ns      4026901 ns          172
BM_FFT_Fp256_2/65536     18797363 ns     18797378 ns           37
BM_FFT_Fp256_2/262144    87642167 ns     87641875 ns            8
BM_FFT_Fp256_2/1048576  446753854 ns    446742500 ns            2
BM_FFT_Fp256_2/4194304 2407741792 ns   2404540000 ns            1
BM_FFT_Fp128/1024           21159 ns        21159 ns        32950
BM_FFT_Fp128/4096          100587 ns       100587 ns         6956
BM_FFT_Fp128/16384         491966 ns       491966 ns         1421
BM_FFT_Fp128/65536        2364386 ns      2364385 ns          296
BM_FFT_Fp128/262144      11986404 ns     11986414 ns           58
BM_FFT_Fp128/1048576     57057522 ns     57053692 ns           13
BM_FFT_Fp128/4194304    328675687 ns    325409000 ns            2
BM_FFT_F64_2/1024           21233 ns        21219 ns        32806
BM_FFT_F64_2/4096          100339 ns        99601 ns         7064
BM_FFT_F64_2/16384         483286 ns       483174 ns         1379
BM_FFT_F64_2/65536        2565717 ns      2474719 ns          302
BM_FFT_F64_2/262144      11513783 ns     11501557 ns           61
BM_FFT_F64_2/1048576     66653771 ns     63372917 ns           12
BM_FFT_F64_2/4194304    319619000 ns    317158000 ns            2
BM_FFT_F64/1024              8731 ns         8552 ns        85701
BM_FFT_F64/4096             36468 ns        36466 ns        19083
BM_FFT_F64/16384           169061 ns       168981 ns         4119
BM_FFT_F64/65536           964327 ns       945066 ns          775
BM_FFT_F64/262144         4254247 ns      4249928 ns          166
BM_FFT_F64/1048576       20092198 ns     20092200 ns           35
BM_FFT_F64/4194304      106302274 ns    106238286 ns            7
```

### SHA
This benchmark measures the time to prove in zero-knowledge the knowledge of a pre-image of size at most N blocks for a given 256-bit string.

```
--------------------------------------------------------------
Benchmark                    Time             CPU   Iterations
--------------------------------------------------------------
BM_ShaZK_fp2_128/1     5300363 ns      5300367 ns          109
BM_ShaZK_fp2_128/2     9602156 ns      9600622 ns           74
BM_ShaZK_fp2_128/4    18730299 ns     18730225 ns           40
BM_ShaZK_fp2_128/8    35389356 ns     35289150 ns           20
BM_ShaZK_fp2_128/16   65615658 ns     65553800 ns           10
BM_ShaZK_fp2_128/32  125226342 ns    125226400 ns            5
BM_ShaZK_fp2_128/33  132710525 ns    132710400 ns            5
```

### ECDSA
Proof of posession of a signature `(r,s)` on a message `e` under public key `(x,y)`.
The combined improvements in our system since our eprint paper have reduced the 
time to prove posession of 1 signature to <17ms.

```
-------------------------------------------------------------------
Benchmark                         Time             CPU   Iterations
-------------------------------------------------------------------
BM_ECDSAZKProver/1         16713685 ns     16713667 ns           42
BM_ECDSAZKProver/2         26511215 ns     26498815 ns           27
BM_ECDSAZKProver/3         38322847 ns     38322889 ns           18
BM_ECDSAZKVerifier/1       10365617 ns     10365627 ns           67
BM_ECDSAZKVerifier/2       16086716 ns     15973932 ns           44
BM_ECDSAZKVerifier/3       23454887 ns     23454323 ns           31
```

