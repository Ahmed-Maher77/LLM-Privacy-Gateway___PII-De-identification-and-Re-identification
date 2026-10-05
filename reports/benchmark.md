# Benchmark

## Cold start

Samples: 1

| sample | import s | construct s | first analyze s | total s |
|---|---|---|---|---|
| 0 | 0.175 | 4.112 | 17.328 | 21.615 |

## Steady-state latency

- Documents: 37 x 1 repeat(s)
- p50: `0.8177s`  p90: `13.6659s`  p99: `28.2783s`  mean: `3.5119s`

  - small: 28 doc(s), p50 `0.5548s`
  - medium: 4 doc(s), p50 `4.8881s`
  - large: 5 doc(s), p50 `14.9828s`

## Throughput and memory by worker count

| workers | docs/s | chars/s | mean latency s | RSS/worker MB (max) |
|---|---|---|---|---|
| 1 | 0.18 | 415.2 | 5.6933 | 2853.2 |
| 2 | 0.27 | 636.2 | 6.7792 | 3428.3 |
