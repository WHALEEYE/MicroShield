# Policy Evaluator

`evaluator.py` will test the correctness and quality of K8s network policies.

### Step 0. Install Weave Scope

To use this evaluator, you should install Weave Scope in advance. Skipped.

### Step 1. Open port forward for Weave Scope

```shell
kubectl port-forward -n weave svc/weave-scope-app 4040:80 --address 0.0.0.0
```

### Step 2. Put policies in specified location

Copy this directory to the master node.

The policies that need to be evaluated should be put under `./policies/`.

### Step 3. Change variables

You should change the variables `ignored_namespaces`, `uuid`, `namespace`, `scope_url` in `evaluate()` to your own settings.

Note that the evaluator will ignore the pods in `ignored_namespaces`, and only take pods with `namespace` as their namespace. Therefore, for most of the time, only one of them are needed to be passed to `get_pod_infos()`.

Also, in `template.py`, you can change the ports that you want to test. The default set is the 1000 top ports by `nmap`.

> If we test all 65535 ports, it will take years. The final ports that will be tested is the union of preset ports and all the ports occurred in policies.

### Step 4. Run evaluator

After running, the evaluator will inject debug containers named `debugger` to every pod that in specified/not ignored namespaces.

Make sure that all the injected containers are in `Running` state, then press enter. You can check the state of these containers with command `kubectl describe [pod_name]`.

Then the evaluator will start to test connections and it might take a long time.

> Be easy, its fully automatic. You just need to wait.

### Arguments

For command line arguments, you can use `-h` flag for more information.

