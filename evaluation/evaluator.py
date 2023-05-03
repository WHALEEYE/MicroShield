#!/bin/python3
import argparse
import ctypes
import json
import multiprocessing
import os
import time
import subprocess
from datetime import datetime
from enum import Enum

import requests
import yaml

import preset

LABEL_PREFIX = "kubernetes_labels_"
NAME_KEY = "kubernetes_name"
NAMESPACE_KEY = "kubernetes_namespace"
IP_ADDRESS_KEY = "kubernetes_ip"
SERVICE_SELECTOR = "kubernetes_selector"
K8S_NS_LABEL = "kubernetes.io/metadata.name"
UUID_KEY = "kubernetes_cluster_uuid"
IGNORED_LABELS = {"controller-revision-hash", "statefulset.kubernetes.io/pod-name"}


def label_matched(conditions, labels):
    for key, value in conditions.items():
        if key not in labels or labels[key] != value:
            return False
    return True


class Endpoint:
    def __init__(self, ip, port, hostname):
        self.ip = ip
        self.port = port
        self.hostname = hostname


class Flow:
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    def __str__(self):
        return f"{self.src.hostname};{self.src.ip};{self.src.port} -> {self.dst.hostname};{self.dst.ip};{self.dst.port}"


class Selector:
    def __init__(self, ns_labels, pod_labels):
        self.ns_labels = ns_labels
        self.pod_labels = pod_labels

    def match(self, pod_info):
        return label_matched(self.ns_labels, pod_info.ns_labels) and label_matched(self.pod_labels, pod_info.labels)


class PodInfo:

    def __init__(self, ns_name, ns_labels, name, labels, ip_address):
        self.ns_name = ns_name
        self.ns_labels = ns_labels
        self.name = name
        self.labels = labels
        self.ip_address = ip_address


class Policy:
    """
    Represents a policy. Each policy object can generate a policy YAML file.
    """

    def __init__(self, name, ns_name, inside_labels, policy_types):
        self.name = name
        self.ns_name = ns_name
        self.inside_labels = inside_labels
        self.ingress_rules = []
        self.egress_rules = []
        self.policy_types = policy_types

    def add_rule(self, direction, rule):
        rules = self.ingress_rules if direction == Direction.INGRESS else self.egress_rules
        rules.append(rule)

    def inside_matched(self, pod_info):
        return label_matched(self.inside_labels, pod_info.labels) and self.ns_name == pod_info.ns_name

    @staticmethod
    def read_from_dict(policy_dict):
        metadata = policy_dict["metadata"]
        spec = policy_dict["spec"]
        policy_name = metadata["name"]
        policy_types = [policy_type.lower() for policy_type in spec["policyTypes"]] if "policyTypes" in spec else []
        policy_selector = spec["podSelector"]["matchLabels"] if "podSelector" in spec else {}
        policy = Policy(policy_name, metadata["namespace"], policy_selector, policy_types)
        if "ingress" in spec:
            for rule in spec["ingress"]:
                selectors = []
                if "from" in rule:
                    for pod in rule["from"]:
                        ns_labels = pod["namespaceSelector"]["matchLabels"] if "namespaceSelector" in pod else {}
                        pod_labels = pod["podSelector"]["matchLabels"] if "podSelector" in pod else {}
                        selectors.append(Selector(ns_labels, pod_labels))
                ports = [preset.get_protocol_port(port["port"]) for port in rule["ports"]] if "ports" in rule else []
                policy.add_rule(Direction.INGRESS, Rule(selectors, ports))
        if "egress" in spec:
            for rule in spec["egress"]:
                selectors = []
                if "to" in rule:
                    for pod in rule["to"]:
                        ns_labels = pod["namespaceSelector"]["matchLabels"] if "namespaceSelector" in pod else {}
                        pod_labels = pod["podSelector"]["matchLabels"] if "podSelector" in pod else {}
                        selectors.append(Selector(ns_labels, pod_labels))
                ports = [preset.get_protocol_port(port["port"]) for port in rule["ports"]] if "ports" in rule else []
                policy.add_rule(Direction.EGRESS, Rule(selectors, ports))
        return policy


class Direction(Enum):
    INGRESS = 1
    EGRESS = 2


class Rule:

    def __init__(self, selectors, ports):
        self.selectors = selectors
        self.ports = ports

    def judge_pod(self, pod_info):
        if not self.selectors:
            return True
        for selector in self.selectors:
            if selector.match(pod_info):
                return True
        return False


class EvaluationReport:
    def __init__(self, true_positive_rate, true_negative_rate, rejection_rate, tp_flows, fp_flows, tn_flows, fn_flows,
                 rejected_flows, open_count, rejected_count):
        self.true_positive_rate = true_positive_rate
        self.true_negative_rate = true_negative_rate
        self.rejection_rate = rejection_rate
        self.tp_flows = tp_flows
        self.fp_flows = fp_flows
        self.tn_flows = tn_flows
        self.fn_flows = fn_flows
        self.rejected_flows = rejected_flows
        self.open_count = open_count
        self.rejected_count = rejected_count

    def get_flows_str(self):
        tp_str = "\n".join([f"{ns}:{name} -> {target_ns}:{target_name}({ip}):{ports}" for
                            (ns, name, ip), (target_ns, target_name, ports) in self.tp_flows.items()])
        fp_str = "\n".join([f"{ns}:{name} -> {target_ns}:{target_name}({ip}):{ports}" for
                            (ns, name, ip), (target_ns, target_name, ports) in self.fp_flows.items()])
        tn_str = "\n".join([f"{ns}:{name} -> {target_ns}:{target_name}({ip}):{ports}" for
                            (ns, name, ip), (target_ns, target_name, ports) in self.tn_flows.items()])
        fn_str = "\n".join([f"{ns}:{name} -> {target_ns}:{target_name}({ip}):{ports}" for
                            (ns, name, ip), (target_ns, target_name, ports) in self.fn_flows.items()])
        rejected_str = "\n".join([f"{ns}:{name} -> {target_ns}:{target_name}({ip}):{ports}" for
                                  (ns, name, ip), (target_ns, target_name, ports) in self.rejected_flows.items()])
        full_tp_str = f"True positive flows:\n{tp_str}\n"
        full_fp_str = f"False positive flows:\n{fp_str}\n"
        full_tn_str = f"True negative flows:\n{tn_str}\n"
        full_fn_str = f"False negative flows:\n{fn_str}\n"
        full_rejected_str = f"Rejected flows:\n{rejected_str}\n"
        return f"{full_tp_str}\n{full_fp_str}\n{full_tn_str}\n{full_fn_str}\n{full_rejected_str}"

    def get_full_report(self):
        return f"True positive rate: {self.true_positive_rate}\n" \
               f"False negative rate: {self.true_negative_rate}\n" \
               f"Rejection rate: {self.rejection_rate}\n" \
               f"> Open count: {self.open_count}\n" \
               f"> Rejected count: {self.rejected_count}\n" \
               f"\nDetailed flow information:\n" \
               f"{self.get_flows_str()}"

    def __str__(self):
        return f"True positive rate: {self.true_positive_rate}\n" \
               f"False negative rate: {self.true_negative_rate}\n" \
               f"Rejection rate: {self.rejection_rate}\n"


def parse_labels(latest_info):
    """
    Parse the label string to a dictionary.
    """
    labels = {}
    for key, value in latest_info.items():
        if key.startswith(LABEL_PREFIX):
            label_name = key[len(LABEL_PREFIX):]
            if label_name in IGNORED_LABELS:
                continue
            labels[key[len(LABEL_PREFIX):]] = value["value"]
    return labels


def assemble_proc_id(host_node_id, pid):
    host_id = host_node_id.split(";")[0]
    return host_id + ";" + pid


def get_pod_info_from_weave(report, uuid=None, ignored_namespaces=None, namespace=None):
    pods = report["Pod"]["nodes"]
    namespaces = report["Namespace"]["nodes"]

    ns_name_to_labels = {}
    for ns_info in namespaces.values():
        latest_info = ns_info["latest"]
        ns_name = latest_info[NAME_KEY]["value"]
        ns_labels = parse_labels(latest_info)
        ns_name_to_labels[ns_name] = ns_labels

    # Extract all pods into a dictionary {pod_id: pod_info}
    pod_id_to_info = {}
    for pod_id, pod_info in pods.items():
        latest_info = pod_info["latest"]

        # Filter code
        # If multi-cluster is enabled, only consider the pods in the specified cluster
        if uuid is not None and latest_info[UUID_KEY]["value"] != uuid:
            continue
        # Ignore the pods with specific namespaces
        if ignored_namespaces is not None and latest_info[NAMESPACE_KEY]["value"] in ignored_namespaces:
            continue
        # Only consider the pods in the specified namespace
        if namespace is not None and latest_info[NAMESPACE_KEY]["value"] not in namespace:
            continue

        pod_name = latest_info[NAME_KEY]["value"]
        pod_ip = latest_info[IP_ADDRESS_KEY]["value"]
        pod_labels = parse_labels(latest_info)
        ns_name = latest_info[NAMESPACE_KEY]["value"]
        ns_labels = ns_name_to_labels[ns_name]

        pod_id_to_info[pod_id] = PodInfo(ns_name, ns_labels, pod_name, pod_labels, pod_ip)

    return pod_id_to_info


def get_pod_info_from_api(ignored_namespaces=None, namespace=None):
    all_pods_info = json.loads(
        subprocess.run(["kubectl", "get", "pods", "-o", "json", "-A"], stdout=subprocess.PIPE).stdout)
    pods = all_pods_info["items"]
    all_ns_info = json.loads(
        subprocess.run(["kubectl", "get", "ns", "-o", "json", "-A"], stdout=subprocess.PIPE).stdout)
    namespaces = all_ns_info["items"]

    ns_name_to_labels = {}
    for ns_info in namespaces:
        metadata = ns_info["metadata"]
        ns_name_to_labels[metadata["name"]] = metadata["labels"]

    cur_pod_id = 0
    # Extract all pods into a dictionary {pod_id: pod_info}
    pod_id_to_info = {}
    for pod_info in pods:
        metadata = pod_info["metadata"]

        # Filter code
        # Ignore the pods with specific namespaces
        if ignored_namespaces is not None and metadata["namespace"] in ignored_namespaces:
            continue
        # Only consider the pods in the specified namespace
        if namespace is not None and metadata["namespace"] not in namespace:
            continue

        pod_name = metadata["name"]
        pod_ip = pod_info["status"]["podIP"]
        pod_labels = metadata["labels"]
        ns_name = metadata["namespace"]
        ns_labels = ns_name_to_labels[ns_name]

        pod_id_to_info[cur_pod_id] = PodInfo(ns_name, ns_labels, pod_name, pod_labels, pod_ip)
        cur_pod_id += 1
        
    return pod_id_to_info


def get_policy_flows(policy_dicts, pod_id_to_info):
    all_ports = preset.get_preset_ports()

    # Read all policies into a dictionary {policy_name: policy_object}
    policies = {}
    for policy_dict in policy_dicts:
        policy = Policy.read_from_dict(policy_dict)
        policies[policy.name] = policy

    allowed_flows = {}
    # initialize, {-2} means no policy is applied
    for src_pod_id in pod_id_to_info:
        for dst_pod_id in pod_id_to_info:
            if src_pod_id == dst_pod_id:
                continue
            allowed_flows[(src_pod_id, dst_pod_id)] = [{-2}, {-2}]

    # for each policy, add the flows that are allowed by the policy into the allowed flows list
    for policy in policies.values():
        # get the ID of all pods that are selected by the policy
        inside_pod_ids = []
        for pod_id, pod_info in pod_id_to_info.items():
            if policy.inside_matched(pod_info):
                inside_pod_ids.append(pod_id)

        if not inside_pod_ids:
            continue

        # set all the flows that related to this policy as forbidden
        for inside_pod_id in inside_pod_ids:
            for pod_id in pod_id_to_info.keys():
                if pod_id == inside_pod_id:
                    continue
                # if the flow is selected by the policy, then initialize it
                if "ingress" not in policy.policy_types:
                    allowed_flows[(pod_id, inside_pod_id)][0] |= {-1}
                elif allowed_flows[(pod_id, inside_pod_id)][0] == {-2}:
                    allowed_flows[(pod_id, inside_pod_id)][0] = set()
                if "egress" not in policy.policy_types:
                    allowed_flows[(inside_pod_id, pod_id)][1] |= {-1}
                elif allowed_flows[(inside_pod_id, pod_id)][1] == {-2}:
                    allowed_flows[(inside_pod_id, pod_id)][1] = set()

        for rule in policy.ingress_rules:
            if "ingress" not in policy.policy_types:
                break
            all_ports |= set(rule.ports)
            for pod_id, pod_info in pod_id_to_info.items():
                if not rule.judge_pod(pod_info):
                    continue
                for inside_pod_id in inside_pod_ids:
                    if inside_pod_id == pod_id:
                        continue
                    ports = set(rule.ports) if rule.ports else {-1}
                    allowed_flows[(pod_id, inside_pod_id)][0] |= ports
        for rule in policy.egress_rules:
            if "egress" not in policy.policy_types:
                break
            all_ports |= set(rule.ports)
            for pod_id, pod_info in pod_id_to_info.items():
                if not rule.judge_pod(pod_info):
                    continue
                for inside_pod_id in inside_pod_ids:
                    if inside_pod_id == pod_id:
                        continue
                    ports = set(rule.ports) if rule.ports else {-1}
                    allowed_flows[(inside_pod_id, pod_id)][1] |= ports

    # use a dictionary to store the flows in policies of each pod
    # {(src_pod_ns, src_pod_name, dst_pod_ip): (allowed_ports, forbidden_ports)}
    policy_flows = {}

    for (src_pod_id, dst_pod_id), (ingress_ports, egress_ports) in allowed_flows.items():
        # if the flow allows all ports or have no corresponding policy, then allow all ports
        if -1 in ingress_ports or -2 in ingress_ports:
            ingress_ports = all_ports
        if -1 in egress_ports or -2 in egress_ports:
            egress_ports = all_ports
        src_pod_info = pod_id_to_info[src_pod_id]
        dst_pod_info = pod_id_to_info[dst_pod_id]
        key = (src_pod_info.ns_name, src_pod_info.name, dst_pod_info.ip_address)
        allowed_ports = ingress_ports & egress_ports
        forbidden_ports = all_ports - allowed_ports
        policy_flows[key] = (dst_pod_info.ns_name, dst_pod_info.name, allowed_ports, forbidden_ports)

    return policy_flows, all_ports


def evaluate_one_pod_ip(namespace, name, ips, is_exp, finished_num, lock):
    for ip in ips:
        os.system(
            f"kubectl exec -n {namespace} {name} -c debugger -- /tmp/evaluation_script.sh {namespace} {name} {ip}{' exp' if is_exp else ''}")
    lock.acquire()
    try:
        finished_num.value += 1
    finally:
        lock.release()


def evaluate_all_pods_multiprocess(pod_infos, is_exp):
    all_ips = [pod_info.ip_address for pod_info in pod_infos]
    ip_num = len(all_ips)
    pod_num = len(pod_infos)

    # set ip pool size
    if pn == 0:
        ip_pool_size = 1
    elif pn == -1:
        ip_pool_size = ip_num
    elif pn == -2:
        ip_pool_size = ip_num // 3
    elif pn < pod_num:
        ip_pool_size = ip_num
    elif pn > pod_num * ip_num:
        ip_pool_size = 1
    else:
        ip_pool_size = ip_num // (pn // pod_num)

    finished_num = multiprocessing.Value(ctypes.c_int, 0)
    processes = []
    lock = multiprocessing.Lock()
    for pod_info in pod_infos:
        for index in range(0, len(all_ips), ip_pool_size):
            ips = all_ips[index:index + ip_pool_size]
            p = multiprocessing.Process(target=evaluate_one_pod_ip,
                                        args=(pod_info.ns_name, pod_info.name, ips, is_exp, finished_num, lock))
            processes.append(p)
    i = 0
    total = len(processes)
    print(f"The evaluation will run in {total} processes.")
    for p in processes:
        p.start()
    while finished_num.value < total:
        i = (i + 1) % 4
        loading = ["|", "/", "-", "\\"][i]
        print(f"\r{loading} Finished: \033[1m{finished_num.value}/{total}\033[0m", end="")
        time.sleep(0.2)
    finish_icon = "✓"
    print(f"\r{finish_icon} Finished: \033[1m{finished_num.value}/{total}\033[0m")
    for p in processes:
        p.join()


def parse_output_files(output_dir):
    flows = {}

    for file in os.listdir(output_dir):
        open_ports = set()
        closed_ports = set()
        forbidden_ports = set()
        with open(os.path.join(output_dir, file)) as f:
            lines = f.read().splitlines()
        key_list = lines[0].split()
        key = (key_list[0].strip(), key_list[1].strip(), key_list[2].strip())
        for line in lines[1:]:
            if not line:
                continue
            if "open" in line:
                open_ports.add(int(line.split()[0]))
            elif "timed out" in line:
                forbidden_ports.add(int(line.split()[0]))
            else:
                closed_ports.add(int(line.strip()))
        flows[key] = (open_ports, closed_ports, forbidden_ports)

    return flows


def calculate_statistics(policy_flows, control_flows, exp_flows):
    true_positive_count = 0
    false_negative_count = 0
    positive_count = 0
    negative_count = 0
    rejected_count = 0
    open_count = 0
    true_positive_flows = {}
    false_positive_flows = {}
    true_negative_flows = {}
    false_negative_flows = {}
    rejected_flows = {}

    for key, (target_ns, target_name, policy_allowed_ports, policy_forbidden_ports) in policy_flows.items():
        (control_open_ports, control_closed_ports, _) = control_flows[key]
        (exp_open_ports, exp_closed_ports, exp_forbidden_ports) = exp_flows[key]

        # calculate anticipatory statistics
        positive_count += len(policy_allowed_ports)
        negative_count += len(policy_forbidden_ports)

        # get port sets
        exp_allowed_ports = exp_open_ports | exp_closed_ports
        true_positive_ports = exp_allowed_ports & policy_allowed_ports
        false_positive_ports = exp_forbidden_ports & policy_allowed_ports
        true_negative_ports = exp_forbidden_ports & policy_forbidden_ports
        false_negative_ports = exp_allowed_ports & policy_forbidden_ports
        rejected_ports = control_open_ports - exp_open_ports

        # calculate tp & fn statistics
        true_positive_count += len(true_positive_ports)
        false_negative_count += len(false_negative_ports)

        # calculate rejection statistics
        open_count += len(control_open_ports)
        rejected_count += len(rejected_ports)

        # store four category of flows
        if true_positive_ports:
            true_positive_flows[key] = (target_ns, target_name, true_positive_ports)
        if false_positive_ports:
            false_positive_flows[key] = (target_ns, target_name, false_positive_ports)
        if true_negative_ports:
            true_negative_flows[key] = (target_ns, target_name, true_negative_ports)
        if false_negative_ports:
            false_negative_flows[key] = (target_ns, target_name, false_negative_ports)
        if rejected_ports:
            rejected_flows[key] = (target_ns, target_name, rejected_ports)

    true_positive_rate = true_positive_count / positive_count if positive_count > 0 else 1.0
    false_negative_rate = false_negative_count / negative_count if negative_count > 0 else 0.0
    rejection_rate = rejected_count / open_count if open_count > 0 else 0.0

    return EvaluationReport(true_positive_rate, false_negative_rate, rejection_rate, true_positive_flows,
                            false_positive_flows, true_negative_flows, false_negative_flows, rejected_flows, open_count, rejected_count)


def collect_evaluation_results(pod_id_to_info, outs_dir):
    finished = 0
    total = len(pod_id_to_info)
    for info in pod_id_to_info.values():
        loading = ["|", "/", "-", "\\"][finished % 4]
        print(f"\r{loading} Finished: \033[1m{finished}/{total}\033[0m", end="")
        os.system(f"kubectl cp {info.ns_name}/{info.name}:tmp/outs {outs_dir} -c debugger")
        finished += 1
    finish_icon = "✓"
    print(f"\r{finish_icon} Finished: \033[1m{finished}/{total}\033[0m")


def data_preparation(pod_id_to_info, root_dir):
    finished = 0
    total = len(pod_id_to_info)
    for info in pod_id_to_info.values():
        loading = ["|", "/", "-", "\\"][finished % 4]
        print(f"\r{loading} Finished: \033[1m{finished}/{total}\033[0m", end="")
        os.system(f"kubectl cp {root_dir}/all_ports {info.ns_name}/{info.name}:/tmp/ -c debugger")
        os.system(f"kubectl cp {root_dir}/evaluation_script.sh {info.ns_name}/{info.name}:/tmp/ -c debugger")
        os.system(f"kubectl exec -n {info.ns_name} {info.name} -c debugger -- rm -rf /tmp/outs")
        finished += 1
    finish_icon = "✓"
    print(f"\r{finish_icon} Finished: \033[1m{finished}/{total}\033[0m")


def evaluate():
    # prepare data
    ignored_namespaces = {"kube-system", "kube-public", "kube-node-lease", "cattle-system", "fleet-system",
                          "ingress-nginx", "weave", "calico-system", "calico-apiserver"}
    namespace = {"pitstop"}
    
    # paths that will be used
    root_dir = os.path.abspath(os.path.join(__file__, os.pardir))
    policies_dir = os.path.join(root_dir, f"policies")
    result_dir = os.path.join(root_dir, f"results")
    outs_dir = os.path.join(result_dir, "outs")
    outs_control_dir = os.path.join(outs_dir, "control")
    outs_exp_dir = os.path.join(outs_dir, "exp")
    reports_cache_dir = os.path.join(root_dir, "reports_cache")

    # create directories if not exist
    if not os.path.exists(outs_control_dir):
        os.makedirs(outs_control_dir)
    if not os.path.exists(outs_exp_dir):
        os.makedirs(outs_exp_dir)
    if not os.path.exists(reports_cache_dir):
        os.makedirs(reports_cache_dir)

    if not args.report_only:
        # clear the directory
        for file in os.listdir(outs_control_dir):
            os.remove(os.path.join(outs_control_dir, file))
        for file in os.listdir(outs_exp_dir):
            os.remove(os.path.join(outs_exp_dir, file))
    policy_dicts = []
    for policy_file in os.listdir(policies_dir):
        policy_dicts.append(yaml.safe_load(open(os.path.join(policies_dir, policy_file))))

    pod_id_to_info = get_pod_info_from_api(namespace=namespace)
    if len(pod_id_to_info) == 0:
        print(f"\033[31mNumber of valid pods ({len(pod_id_to_info)}) < 2, aborting...\033[0m")
        return
    policy_flows, all_ports = get_policy_flows(policy_dicts, pod_id_to_info)

    # prepare data for evaluation shell scripts
    with open(f"{root_dir}/all_ports", "w") as f:
        f.write(" ".join([str(port) for port in all_ports]))

    if args.report_only or args.skip_injection:
        print("\033[33mSkipped debug container setup.\n\033[0m")
    else:
        # inject debugger containers to pods
        print("\033[33mDeploying debug containers...\033[0m")
        for info in pod_id_to_info.values():
            os.system(f"kubectl debug {info.name} -n {info.ns_name} --image=busybox -c debugger -- sleep 10000000000")
        print("\033[32mAll debug containers are deployed, but it may take some time to set up.\033[0m")
        input("\033[1mPress Enter When All Debuggers Are in RUNNING state.\033[0m")

    if args.report_only:
        print("\033[33mSkipped data preparation.\033[0m\n")
        print("\033[33mSkipped evaluation.\033[0m\n")
    else:
        # prepare script and data for debugger containers
        print("\033[33mPreparing data in debugger containers...\033[0m")
        data_preparation(pod_id_to_info, root_dir)
        print("\033[32mData in debugger containers are prepared.\033[0m\n")

        # multiprocessing control evaluation
        print("\033[33mControl evaluation started...\033[0m")
        evaluate_all_pods_multiprocess(pod_id_to_info.values(), False)
        print("\033[32mControl evaluation finished.\033[0m\n")

        # apply policies
        print("\033[33mApplying policies...\033[0m")
        os.system(f"kubectl apply -f {policies_dir}")
        print("\033[32mPolicies applied.\033[0m\n")

        # multiprocessing experimental evaluation
        print("\033[33mExperimental evaluation started...\033[0m")
        evaluate_all_pods_multiprocess(pod_id_to_info.values(), True)
        print("\033[32mExperimental evaluation finished.\033[0m\n")

        # delete policies
        print("\033[33mDeleting policies...\033[0m")
        os.system(f"kubectl delete -f {policies_dir}")
        print("\033[32mPolicies deleted.\033[0m\n")

        # collect evaluation results
        print("\033[33mCollecting evaluation results...\033[0m")
        collect_evaluation_results(pod_id_to_info, outs_dir)
        print("\033[32mEvaluation results collected.\033[0m\n")

        print("\033[;32;1mALL DONE!\033[0m\n")

    # generate evaluation report
    print("\033[33mGenerating evaluation report...\033[0m")
    control_flows = parse_output_files(outs_control_dir)
    exp_flows = parse_output_files(outs_exp_dir)
    evaluation_report = calculate_statistics(policy_flows, control_flows, exp_flows)
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    print(f"\nGenerated at {timestamp}:")
    print(f"\033[36m{evaluation_report}\033[0m")

    report_file_path = f"{result_dir}/report.txt"
    report_cache_file_path = f"{reports_cache_dir}/{timestamp}.txt"
    with open(report_file_path, "w") as f:
        f.write(evaluation_report.get_full_report())
    with open(report_cache_file_path, "w") as f:
        f.write(evaluation_report.get_full_report())
    print(f"Full evaluation report generated at {report_file_path}.")


if __name__ == "__main__":
    arguments = argparse.ArgumentParser()
    arguments.add_argument("-r", "--report-only",
                           help="Only generate reports. "
                                "This should not be used for the first time or at long time after last evaluation.",
                           action="store_true", default=False)
    arguments.add_argument("-s", "--skip-injection",
                           help="Skip the injection of debug containers. This should not used for the first time.",
                           action="store_true", default=False)
    arguments.add_argument("-p", "--process-number",
                           help="Number of processes. Max is [pod_num * ip_num]. "
                                "Min is [pod_num]. You can specify a number between them or input max/min. "
                                "Note that the actual process number may be slightly different.",
                           default="-2")
    args = arguments.parse_args()
    if args.process_number == "max":
        pn = 0
    elif args.process_number == "min":
        pn = -1
    else:
        pn = int(args.process_number)
    evaluate()

