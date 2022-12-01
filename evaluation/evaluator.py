#!/bin/python3
import argparse
import ctypes
import json
import multiprocessing
import os
import time
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

    def __init__(self, name, ns_labels, inside_labels, policy_types):
        self.name = name
        self.inside_selector = Selector(ns_labels, inside_labels)
        self.ingress_rules = []
        self.egress_rules = []
        self.policy_types = policy_types

    def add_rule(self, direction, rule):
        rules = self.ingress_rules if direction == Direction.INGRESS else self.egress_rules
        rules.append(rule)

    def judge_flow(self, fr_rsc_info, to_rsc_info, port, direction):
        # Judge if the flow is matched by the policy
        inside_resource_info = to_rsc_info if direction == Direction.INGRESS else fr_rsc_info
        if not self.inside_selector.match(inside_resource_info):
            return False

        # If the policy does not have this direction in policyTypes, the flow is allowed
        if direction.name.lower() not in self.policy_types:
            return True

        # Judge if the flow is allowed by the rules
        rules = self.ingress_rules if direction == Direction.INGRESS else self.egress_rules
        outside_resource_info = fr_rsc_info if direction == Direction.INGRESS else to_rsc_info
        for rule in rules:
            if rule.judge_flow(outside_resource_info, port):
                return True
        return False

    @staticmethod
    def read_from_dict(policy_dict):
        metadata = policy_dict["metadata"]
        spec = policy_dict["spec"]
        policy_name = metadata["name"]
        policy_types = [policy_type.lower() for policy_type in spec["policyTypes"]] if "policyTypes" in spec else []
        policy_selector = spec["podSelector"]["matchLabels"] if "podSelector" in spec else {}
        policy = Policy(policy_name, {K8S_NS_LABEL: metadata["namespace"]}, policy_selector, policy_types)
        if "ingress" in spec:
            for rule in spec["ingress"]:
                selectors = []
                if "from" in rule:
                    for pod in rule["from"]:
                        ns_labels = pod["namespaceSelector"]["matchLabels"] if "namespaceSelector" in pod else {}
                        pod_labels = pod["podSelector"]["matchLabels"] if "podSelector" in pod else {}
                        selectors.append(Selector(ns_labels, pod_labels))
                ports = [port["port"] for port in rule["ports"]] if "ports" in rule else []
                policy.add_rule(Direction.INGRESS, Rule(selectors, ports))
        if "egress" in spec:
            for rule in spec["egress"]:
                selectors = []
                if "to" in rule:
                    for pod in rule["to"]:
                        ns_labels = pod["namespaceSelector"]["matchLabels"] if "namespaceSelector" in pod else {}
                        pod_labels = pod["podSelector"]["matchLabels"] if "podSelector" in pod else {}
                        selectors.append(Selector(ns_labels, pod_labels))
                ports = [port["port"] for port in rule["ports"]] if "ports" in rule else []
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
    def __init__(self, true_positive_rate, true_negative_rate, rejection_rate):
        self.true_positive_rate = true_positive_rate
        self.true_negative_rate = true_negative_rate
        self.rejection_rate = rejection_rate

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


def get_pod_infos(report, uuid=None, ignored_namespaces=None, namespace=None):
    pods = report["Pod"]["nodes"]
    namespaces = report["Namespace"]["nodes"]

    ns_name_to_labels = {}
    for ns_id, ns_info in namespaces.items():
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
            if policy.inside_selector.match(pod_info):
                inside_pod_ids.append(pod_id)

        if not inside_pod_ids:
            continue

        # set all the flows that related to this policy as forbidden
        for inside_pod_id in inside_pod_ids:
            for pod_id in pod_id_to_info.keys():
                if pod_id == inside_pod_id:
                    continue
                # if the pod is not selected by the policy, then initialize it
                if allowed_flows[(pod_id, inside_pod_id)][0] == {-2}:
                    allowed_flows[(pod_id, inside_pod_id)][0] = set()
                if allowed_flows[(inside_pod_id, pod_id)][1] == {-2}:
                    allowed_flows[(inside_pod_id, pod_id)][1] = set()
        for rule in policy.ingress_rules:
            all_ports |= set(rule.ports)
            for pod_id, pod_info in pod_id_to_info.items():
                if pod_id in inside_pod_ids:
                    continue
                if not rule.judge_pod(pod_info):
                    continue
                for inside_pod_id in inside_pod_ids:
                    ports = set(rule.ports) if rule.ports else {-1}
                    allowed_flows[(pod_id, inside_pod_id)][0] |= ports
        for rule in policy.egress_rules:
            all_ports |= set(rule.ports)
            for pod_id, pod_info in pod_id_to_info.items():
                if pod_id in inside_pod_ids:
                    continue
                if not rule.judge_pod(pod_info):
                    continue
                for inside_pod_id in inside_pod_ids:
                    ports = set(rule.ports) if rule.ports else {-1}
                    allowed_flows[(inside_pod_id, pod_id)][1] |= ports

    # use a dictionary to store the flows in policies of each pod
    # {(src_pod_name, src_pod_ns, dst_pod_ip): (allowed_ports, forbidden_ports)}
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
        policy_flows[key] = (allowed_ports, forbidden_ports)

    return policy_flows, all_ports


def evaluate_one_pod_ip(namespace, name, ips, is_exp, finished_num, lock):
    for ip in ips:
        os.system(
            f"kubectl exec -n {namespace} {name} -c debugger -- /evaluation_script.sh {namespace} {name} {ip}{' exp' if is_exp else ''}")
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

    for key, (policy_allowed_ports, policy_forbidden_ports) in policy_flows.items():
        (control_open_ports, control_closed_ports, _) = control_flows[key]
        (exp_open_ports, exp_closed_ports, exp_forbidden_ports) = exp_flows[key]

        # calculate anticipatory statistics
        positive_count += len(policy_allowed_ports)
        negative_count += len(policy_forbidden_ports)

        # calculate tp & fn statistics
        exp_allowed_ports = exp_open_ports | exp_closed_ports
        true_positive_count += len(exp_allowed_ports & policy_allowed_ports)
        false_negative_count += len(exp_allowed_ports & policy_forbidden_ports)

        # calculate rejection statistics
        open_count += len(control_open_ports)
        rejected_count += len(control_open_ports - exp_open_ports)

    true_positive_rate = true_positive_count / positive_count if positive_count > 0 else 1.0
    false_negative_rate = false_negative_count / negative_count if negative_count > 0 else 0.0
    rejection_rate = rejected_count / open_count if open_count > 0 else 0.0

    return EvaluationReport(true_positive_rate, false_negative_rate, rejection_rate)


def collect_evaluation_results(pod_id_to_info, outs_dir):
    finished = 0
    total = len(pod_id_to_info)
    for info in pod_id_to_info.values():
        loading = ["|", "/", "-", "\\"][finished % 4]
        print(f"\r{loading} Finished: \033[1m{finished}/{total}\033[0m", end="")
        os.system(f"kubectl cp {info.ns_name}/{info.name}:outs {outs_dir} -c debugger")
        finished += 1
    finish_icon = "✓"
    print(f"\r{finish_icon} Finished: \033[1m{finished}/{total}\033[0m")


def data_preparation(pod_id_to_info, root_dir):
    finished = 0
    total = len(pod_id_to_info)
    for info in pod_id_to_info.values():
        loading = ["|", "/", "-", "\\"][finished % 4]
        print(f"\r{loading} Finished: \033[1m{finished}/{total}\033[0m", end="")
        os.system(f"kubectl cp {root_dir}/all_ports {info.ns_name}/{info.name}:/ -c debugger")
        os.system(f"kubectl cp {root_dir}/evaluation_script.sh {info.ns_name}/{info.name}:/ -c debugger")
        os.system(f"kubectl exec -n {info.ns_name} {info.name} -c debugger -- rm -rf /outs")
        finished += 1
    finish_icon = "✓"
    print(f"\r{finish_icon} Finished: \033[1m{finished}/{total}\033[0m")


def evaluate():
    # paths that will be used
    root_dir = os.path.abspath(os.path.join(__file__, os.pardir))
    policies_dir = os.path.join(root_dir, "policies")
    outs_dir = os.path.join(root_dir, "outs")
    outs_control_dir = os.path.join(outs_dir, "control")
    outs_exp_dir = os.path.join(outs_dir, "exp")
    reports_dir = os.path.join(root_dir, "reports")

    # create directories if not exist
    if not os.path.exists(outs_control_dir):
        os.makedirs(outs_control_dir)
    if not os.path.exists(outs_exp_dir):
        os.makedirs(outs_exp_dir)
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    if not args.report_only:
        # clear the directory
        for file in os.listdir(outs_control_dir):
            os.remove(os.path.join(outs_control_dir, file))
        for file in os.listdir(outs_exp_dir):
            os.remove(os.path.join(outs_exp_dir, file))

    # prepare data
    ignored_namespaces = {"kube-system", "kube-public", "kube-node-lease", "cattle-system", "fleet-system",
                          "ingress-nginx", "weave", "calico-system", "calico-apiserver"}
    uuid = "33d1901faed141cf8ccacf5e94961607"
    namespace = {"sock-shop"}
    scope_url = "http://192.168.218.133:4040"
    report_raw_json = requests.get(f"{scope_url}/api/report")
    report = json.loads(report_raw_json.content.decode())
    policy_dicts = []
    for policy_file in os.listdir(policies_dir):
        policy_dicts.append(yaml.safe_load(open(os.path.join(policies_dir, policy_file))))

    pod_id_to_info = get_pod_infos(report, namespace=namespace)
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

    report_file = f"{reports_dir}/{timestamp}"
    with open(report_file, "w") as f:
        f.write(evaluation_report.__str__())
    print(f"Evaluation report generated at {report_file}.")


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
