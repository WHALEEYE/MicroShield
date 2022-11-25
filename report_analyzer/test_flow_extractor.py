import json
import os
import time
from enum import Enum

import yaml

LABEL_PREFIX = "kubernetes_labels_"
NAME_KEY = "kubernetes_name"
NAMESPACE_KEY = "kubernetes_namespace"
IP_ADDRESS_KEY = "kubernetes_ip"
SERVICE_SELECTOR = "kubernetes_selector"
K8S_NS_LABEL = "kubernetes.io/metadata.name"
UUID_KEY = "kubernetes_cluster_uuid"
IGNORED_LABELS = {"controller-revision-hash", "statefulset.kubernetes.io/pod-name"}
SMALLEST_PORT = 1
LARGEST_PORT = 65536


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
    def __init__(self, labels, namespace):
        self.labels = labels
        self.namespace = namespace

    def match(self, pod_info):
        return label_matched(self.labels, pod_info.labels) and self.namespace == pod_info.namespace


class PodInfo:

    def __init__(self, name, labels, namespace, ip_address):
        self.name = name
        self.labels = labels
        self.namespace = namespace
        self.ip_address = ip_address


class Policy:
    """
    Represents a policy. Each policy object can generate a policy YAML file.
    """

    def __init__(self, name, inside_labels, namespace, policy_types):
        self.name = name
        self.inside_selector = Selector(inside_labels, namespace)
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
        policy_types = [policy_type.lower() for policy_type in spec["policyTypes"]]
        policy_selector = {}
        if "podSelector" in spec:
            policy_selector = spec["podSelector"]["matchLabels"]
        policy = Policy(policy_name, policy_selector, metadata["namespace"], policy_types)
        if "ingress" in spec:
            for rule in spec["ingress"]:
                selectors = []
                if "from" in rule:
                    for pod in rule["from"]:
                        pod_labels = pod["podSelector"]["matchLabels"]
                        pod_ns = pod["namespaceSelector"]["matchLabels"][K8S_NS_LABEL]
                        selectors.append(Selector(pod_labels, pod_ns))
                ports = []
                if "ports" in rule:
                    ports = [port["port"] for port in rule["ports"]]
                policy.add_rule(Direction.INGRESS, Rule(selectors, ports))
        if "egress" in spec:
            for rule in spec["egress"]:
                selectors = []
                if "to" in rule:
                    for pod in rule["to"]:
                        pod_labels = pod["podSelector"]["matchLabels"]
                        pod_ns = pod["namespaceSelector"]["matchLabels"][K8S_NS_LABEL]
                        selectors.append(Selector(pod_labels, pod_ns))
                ports = []
                if "ports" in rule:
                    ports = [port["port"] for port in rule["ports"]]
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


def generate_test_info(static_policy_dicts, report, uuid, ignored_namespaces):
    pods = report["Pod"]["nodes"]
    # Extract all pods into a dictionary {pod_id: pod_info}
    pod_id_to_info = {}
    for pod_id, pod_info in pods.items():
        latest_info = pod_info["latest"]
        # If multi-cluster is enabled, only consider the pods in the specified cluster
        if uuid is not None and latest_info[UUID_KEY]["value"] != uuid:
            continue
        # Ignore the pods with specific namespaces
        if ignored_namespaces is not None and latest_info[NAMESPACE_KEY]["value"] in ignored_namespaces:
            continue
        pod_name = latest_info[NAME_KEY]["value"]
        pod_ns = latest_info[NAMESPACE_KEY]["value"]
        pod_ip = latest_info[IP_ADDRESS_KEY]["value"]
        pod_labels = parse_labels(latest_info)
        pod_id_to_info[pod_id] = PodInfo(pod_name, pod_labels, pod_ns, pod_ip)

    # Read all policies into a dictionary {policy_name: policy_object}
    static_policies = {}
    for policy_dict in static_policy_dicts:
        policy = Policy.read_from_dict(policy_dict)
        static_policies[policy.name] = policy

    # For each policy, add the flows that are allowed by the policy into the allowed flows list
    allowed_flows = {}
    for policy in static_policies.values():
        inside_pod_ids = []
        for pod_id, pod_info in pod_id_to_info.items():
            if policy.inside_selector.match(pod_info):
                inside_pod_ids.append(pod_id)
        if not inside_pod_ids:
            continue
        for pod_id, pod_info in pod_id_to_info.items():
            for rule in policy.egress_rules:
                if not rule.judge_pod(pod_info):
                    continue
                for inside_pod_id in inside_pod_ids:
                    ports = rule.ports if rule.ports else [i for i in range(SMALLEST_PORT, LARGEST_PORT)]
                    for port in ports:
                        if (inside_pod_id, pod_id, port) not in allowed_flows:
                            allowed_flows[(inside_pod_id, pod_id, port)] = [False, False]
                        allowed_flows[(inside_pod_id, pod_id, port)][0] = True
            for rule in policy.ingress_rules:
                if not rule.judge_pod(pod_info):
                    continue
                for inside_pod_id in inside_pod_ids:
                    ports = rule.ports if rule.ports else [i for i in range(SMALLEST_PORT, LARGEST_PORT)]
                    for port in ports:
                        if (pod_id, inside_pod_id, port) not in allowed_flows:
                            allowed_flows[(pod_id, inside_pod_id, port)] = [False, False]
                        allowed_flows[(pod_id, inside_pod_id, port)][1] = True

    # Use a dictionary to store the possible flows of each pod {(src_pod_name, src_pod_ns): [test_flow_object]}
    all_possible_flows = {}
    # For each possible flow, if it is not in the allowed flows list, it is blocked by the policy
    for pod_id, pod_info in pod_id_to_info.items():
        temp_flows = []
        for other_pod_id, other_pod_info in pod_id_to_info.items():
            if pod_id == other_pod_id:
                continue
            for port in range(SMALLEST_PORT, LARGEST_PORT):
                if (pod_id, other_pod_id, port) not in allowed_flows:
                    temp_flows.append((other_pod_info, port, False))
                else:
                    expected_result = allowed_flows[(pod_id, other_pod_id, port)][0] and \
                                      allowed_flows[(pod_id, other_pod_id, port)][1]
                    temp_flows.append((other_pod_info, port, expected_result))
        all_possible_flows[(pod_info.name, pod_info.namespace, pod_info.ip_address)] = temp_flows

    return all_possible_flows


def example_use_case():
    data_dir = os.path.abspath(os.path.join(__file__, os.pardir, "test_data"))
    par_dir = os.path.abspath(os.path.join(__file__, os.pardir))
    ignored_namespaces = {"kube-system", "kube-public", "kube-node-lease", "cattle-system", "fleet-system",
                          "ingress-nginx", "weave", "calico-system", "calico-apiserver"}
    uuid = "33d1901faed141cf8ccacf5e94961607"
    report = json.load(open(f"{data_dir}/report.json"))
    static_policies = []
    for test_static_file in os.listdir(f"{data_dir}/static_policies"):
        static_policies.append(
            yaml.safe_load(open(os.path.join(f"{data_dir}/static_policies", test_static_file))))
    all_possible_flows = generate_test_info(static_policies, report, uuid, ignored_namespaces)

    # Export the result to a file
    with open(f"{par_dir}/test_result.txt", "w") as f:
        for src_pod, flows in all_possible_flows.items():
            f.write(f"{src_pod[0]} {src_pod[1]} ({src_pod[2]})\n")
            for flow in flows:
                f.write(f"    {flow[0].ip_address} {flow[1]} {flow[2]}\n")


if __name__ == "__main__":
    start_time = time.time()
    example_use_case()
