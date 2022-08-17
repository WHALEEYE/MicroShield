#!/bin/bash

kubectl logs -n weave -l name=weave-scope-agent -f | grep "\[CONN\] \[eBPF\]" | ./ws_server.py
