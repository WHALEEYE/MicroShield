import json
import os
import time
from enum import Enum

import yaml

from .logger import Logger, Mode

LABEL_PREFIX = "kubernetes_labels_"
NAME_KEY = "kubernetes_name"
NAMESPACE_KEY = "kubernetes_namespace"
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
    def __init__(self, labels, namespace):
        self.selector = labels
        self.namespace = namespace

    def match(self, resource_info):
        return label_matched(self.selector, resource_info.labels) and self.namespace == resource_info.namespace


class ResourceInfo:

    def __init__(self, resource_name, labels, namespace, resource_type):
        self.resource_name = resource_name
        self.labels = labels
        self.namespace = namespace
        self.resource_type = resource_type

    def get_canonical_name(self):
        return f"{self.resource_type.name.lower()}-{self.resource_name}-{self.namespace}"


class Policy:
    """
    Represents a policy. Each policy object can generate a policy YAML file.
    """

    def __init__(self, name, inside_labels, namespace, policy_types):
        self.name = name
        self.inside_labels = inside_labels
        self.namespace = namespace
        self.ingress_rules = []
        self.egress_rules = []
        self.policy_types = policy_types

    def add_rule(self, direction, rule):
        rules = self.ingress_rules if direction == Direction.INGRESS else self.egress_rules
        rules.append(rule)

    def judge_flow(self, fr_rsc_info, to_rsc_info, port, direction):
        # Judge if the flow is matched by the policy
        inside_resource_info = to_rsc_info if direction == Direction.INGRESS else fr_rsc_info
        if not label_matched(self.inside_labels,
                             inside_resource_info.labels) or self.namespace != inside_resource_info.namespace:
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


class ResourceType(Enum):
    POD = 1
    DEPLOYMENT = 2


class Rule:

    def __init__(self, selectors, ports):
        self.selectors = selectors
        self.ports = ports

    def judge_flow(self, resource_info, port):
        """
        Judge if this rule allows the flow passes.
        If the flow is allowed, return True.
        If the flow is not allowed or not matched, return False.
        """
        if self.ports and port not in self.ports:
            return False
        if not self.selectors:
            return True
        for selector in self.selectors:
            if selector.match(resource_info):
                return True
        return False

    def add_port(self, port):
        if port not in self.ports:
            self.ports.append(port)


def get_parent_id(info, parent_type):
    if "parents" in info and info["parents"] is not None:
        if parent_type in info["parents"]:
            return info["parents"][parent_type][0]
    return None


def parse_label(latest_info):
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


def compare(static_policy_dicts, report, uuid, ignored_namespaces):
    proc_to_pod = {}
    enp_to_pod = {}
    enp_to_adj = {}
    enp_to_info = {}
    pod_id_to_rsc_info = {}
    resource_id_to_info = {}

    static_policies = {}
    for policy_dict in static_policy_dicts:
        policy = Policy.read_from_dict(policy_dict)
        static_policies[policy.name] = policy

    enps = report["Endpoint"]["nodes"]
    procs = report["Process"]["nodes"]
    ctns = report["Container"]["nodes"]
    pods = report["Pod"]["nodes"]
    deps = report["Deployment"]["nodes"]

    for proc_id, proc_info in procs.items():
        parent_ctn_id = get_parent_id(proc_info, "container")
        if parent_ctn_id not in ctns:
            continue
        prt_pod_id = get_parent_id(ctns[parent_ctn_id], "pod")
        if prt_pod_id not in pods:
            continue
        if pods[prt_pod_id]["latest"][UUID_KEY]["value"] != uuid:
            continue
        # ignore the pods with specific namespaces
        if pods[prt_pod_id]["latest"][NAMESPACE_KEY]["value"] in ignored_namespaces:
            continue
        proc_to_pod[proc_id] = prt_pod_id

    for enp_id, enp_info in enps.items():
        enp_to_adj[enp_id] = enp_info["adjacency"] if "adjacency" in enp_info else []
        if "latest" not in enp_info:
            continue
        enp_latest = enp_info["latest"]
        if "host_node_id" not in enp_latest or "pid" not in enp_latest:
            continue
        host_node_id = enp_latest["host_node_id"]["value"]
        proc_id = assemble_proc_id(host_node_id, enp_latest["pid"]["value"])
        enp_to_info[enp_id] = Endpoint(enp_id.split(";")[-2], enp_id.split(";")[-1], host_node_id.split(";")[0])
        if proc_id not in proc_to_pod:
            continue
        enp_to_pod[enp_id] = proc_to_pod[proc_id]

    for pod_id, pod_info in pods.items():
        pod_latest = pod_info["latest"]
        labels = parse_label(pod_latest)
        namespace = pod_latest[NAMESPACE_KEY]["value"]
        pod_name = pod_latest[NAME_KEY]["value"]
        prt_dep_id = get_parent_id(pods[pod_id], "deployment")
        resource_name = pod_name
        resource_id = pod_id
        resource_type = ResourceType.POD
        if prt_dep_id in deps and "latest" in deps[prt_dep_id]:
            resource_id = prt_dep_id
            resource_type = ResourceType.DEPLOYMENT
            resource_name = deps[prt_dep_id]["latest"][NAME_KEY]["value"]
        if resource_id not in resource_id_to_info:
            resource_id_to_info[resource_id] = ResourceInfo(resource_name, labels, namespace, resource_type)
        pod_id_to_rsc_info[pod_id] = resource_id_to_info[resource_id]

    abnormal_flows = []

    # Go through all the flows to find the abnormal flows
    for fr_enp_id, fr_pod_id in enp_to_pod.items():
        to_enps = enp_to_adj[fr_enp_id]
        for to_enp_id in to_enps:
            if to_enp_id not in enp_to_pod:
                continue
            to_pod_id = enp_to_pod[to_enp_id]
            if to_pod_id == fr_pod_id:
                continue
            to_rsc_info = pod_id_to_rsc_info[to_pod_id]
            fr_rsc_info = pod_id_to_rsc_info[fr_pod_id]
            port = int(to_enp_id.split(";")[-1])

            ingress_allow = False
            egress_allow = False
            allowed = False

            # the policies with the same canonical name will have higher priority
            if to_rsc_info.get_canonical_name() in static_policies:
                policy = static_policies[to_rsc_info.get_canonical_name()]
                if policy.judge_flow(fr_rsc_info, to_rsc_info, port, Direction.INGRESS):
                    ingress_allow = True
            if fr_rsc_info.get_canonical_name() in static_policies:
                policy = static_policies[fr_rsc_info.get_canonical_name()]
                if policy.judge_flow(fr_rsc_info, to_rsc_info, port, Direction.EGRESS):
                    egress_allow = True
            if ingress_allow and egress_allow:
                continue

            # Fallback: go through all the policies
            for policy in static_policies.values():
                if policy.judge_flow(fr_rsc_info, to_rsc_info, port, Direction.INGRESS):
                    ingress_allow = True
                if policy.judge_flow(fr_rsc_info, to_rsc_info, port, Direction.EGRESS):
                    egress_allow = True
                if ingress_allow and egress_allow:
                    allowed = True
                    break

            if not allowed:
                abnormal_flows.append(Flow(enp_to_info[fr_enp_id], enp_to_info[to_enp_id]))

    return abnormal_flows


def example_use_case():
    data_dir = os.path.abspath(os.path.join(__file__, os.pardir, "test_data"))
    ignored_namespaces = {"kube-system", "kube-public", "kube-node-lease", "cattle-system", "fleet-system",
                          "ingress-nginx", "weave", "calico-system", "calico-apiserver"}
    uuid = "33d1901faed141cf8ccacf5e94961607"
    report = json.load(open(f"{data_dir}/report.json"))
    static_policies = []
    for test_static_file in os.listdir(f"{data_dir}/static_policies"):
        static_policies.append(
            yaml.safe_load(open(os.path.join(f"{data_dir}/static_policies", test_static_file))))
    abnormal_flows = compare(static_policies, report, uuid, ignored_namespaces)

    # print the abnormal flows for test
    for abnormal_flow in abnormal_flows:
        logger.debug(abnormal_flow)


if __name__ == "__main__":
    logger = Logger(Mode.DEBUG)
    start_time = time.time()
    example_use_case()
    logger.info("Time used: " + str(time.time() - start_time))
