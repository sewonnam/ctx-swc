A Simple program to output context-switching counts per process

```
$ make
$ sudo ./swc
Tracing process context-switching count... Ctrl-C to end.
^C
COMM             COUNT
swc              9
ksoftirqd/0      2
sudo             3
gmain            1
systemd-journal  1
kworker/u4:26    1
migration/0      1
migration/1      1
kworker/0:2      6
HangDetector     1
swapper/1        47
rcu_preempt      7
vmtoolsd         16
multipathd       2
sshd             4
multipathd       2
kworker/1:0      12
kcompactd0       3
gmain            1
kworker/u4:1     21
```

reference:
https://github.com/iovisor/bcc/blob/master/libbpf-tools/runqlat.c
