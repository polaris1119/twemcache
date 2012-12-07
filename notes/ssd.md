## Idea

+ ssd as an extension of memory.
+ ssd as an extension of disk.
+ The former makes memory fat, latter makes disk fast.
+ The former makes memory slow, latter makes disk expensive.
+ The former doesn't care about persistence, latter does.
+ The former makes sense when accessed over network, latter always makes sense when costs are not prohibitive.

## mmap, munmap

+ http://www.gnu.org/software/libc/manual/html_node/Memory_002dmapped-I_002fO.html

## References

+ http://www.ramsan.com/
+ http://www.theregister.co.uk/2009/04/13/schooner_memcached_mysql/
+ http://research.microsoft.com/en-us/um/people/antr/ms/ssd.pdf

## tools

+ sudo dd if=/dev/sdb of=./loop_file_10MB bs=1024 count=10K

## Performance

### mmap tests

#### main memory

    $ ./mcperf -s localhost --num-conns=100 --conn-rate=10000 --num-calls=10000 --call-rate=10000

    Total: connections 100 requests 1000000 responses 1000000 test-duration 8.553 s

    Connection rate: 11.7 conn/s (85.5 ms/conn <= 100 concurrent connections)
    Connection time [ms]: avg 8126.0 min 6902.2 max 8548.3 stddev 341.38
    Connect time [ms]: avg 61.7 min 0.2 max 93.3 stddev 41.07

    Request rate: 116923.3 req/s (0.0 ms/req)
    Request size [B]: avg 28.0 min 28.0 max 28.0 stddev 0.00

    Response rate: 116923.3 rsp/s (0.0 ms/rsp)
    Response size [B]: avg 8.0 min 8.0 max 8.0 stddev 0.00
    Response time [ms]: avg 1748.7 min 0.8 max 5775.3 stddev 1.41
    Response time [ms]: p25 361.0 p50 1693.0 p75 2739.0
    Response time [ms]: p95 4037.0 p99 5043.0 p999 5490.0
    Response type: stored 1000000 not_stored 0 exists 0 not_found 0
    Response type: num 0 deleted 0 end 0 value 0
    Response type: error 0 client_error 0 server_error 0

    Errors: total 0 client-timo 0 socket-timo 0 connrefused 0 connreset 0
    Errors: fd-unavail 0 ftab-full 0 addrunavail 0 other 0

    CPU time [s]: user 2.27 system 6.17 (user 26.5% system 72.1% total 98.6%)
    Net I/O: bytes 34.3 MB rate 4110.6 KB/s (33.7*10^6 bps)

#### ssd (251G APPLE SSD SM256C Media)

    $ ./mcperf -s localhost --num-conns=100 --conn-rate=10000 --num-calls=10000 --call-rate=10000

    Total: connections 100 requests 1000000 responses 1000000 test-duration 13.780 s

    Connection rate: 7.3 conn/s (137.8 ms/conn <= 100 concurrent connections)
    Connection time [ms]: avg 13525.3 min 11656.2 max 13778.0 stddev 347.02
    Connect time [ms]: avg 5.0 min 0.1 max 27.1 stddev 6.01

    Request rate: 72568.9 req/s (0.0 ms/req)
    Request size [B]: avg 28.0 min 28.0 max 28.0 stddev 0.00

    Response rate: 72568.9 rsp/s (0.0 ms/rsp)
    Response size [B]: avg 8.0 min 8.0 max 8.0 stddev 0.00
    Response time [ms]: avg 3494.0 min 0.1 max 9246.9 stddev 2.03
    Response time [ms]: p25 1615.0 p50 3931.0 p75 4856.0
    Response time [ms]: p95 6596.0 p99 7658.0 p999 8694.0
    Response type: stored 1000000 not_stored 0 exists 0 not_found 0
    Response type: num 0 deleted 0 end 0 value 0
    Response type: error 0 client_error 0 server_error 0

    Errors: total 0 client-timo 0 socket-timo 0 connrefused 0 connreset 0
    Errors: fd-unavail 0 ftab-full 0 addrunavail 0 other 0

    CPU time [s]: user 3.29 system 8.57 (user 23.9% system 62.2% total 86.1%)
    Net I/O: bytes 34.3 MB rate 2551.3 KB/s (20.9*10^6 bps)

