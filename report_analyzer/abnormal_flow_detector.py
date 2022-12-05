import json
import os
import time
from enum import Enum

import yaml

from logger import Logger, Mode

LABEL_PREFIX = "kubernetes_labels_"
PROC_NAME_KEY = "name"
CTN_NAME_KEY = "docker_label_io.kubernetes.container.name"
POD_NAME_KEY = "kubernetes_name"
DEP_NAME_KEY = "kubernetes_name"
CTN_NAMESPACE_KEY = "docker_label_io.kubernetes.pod.namespace"
POD_NAMESPACE_KEY = "kubernetes_namespace"
SERVICE_SELECTOR = "kubernetes_selector"
K8S_NS_LABEL = "kubernetes.io/metadata.name"
POD_UUID_KEY = "kubernetes_cluster_uuid"
CTN_UUID_KEY = "cluster_uuid"
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
    def __init__(self, ns_labels, labels):
        self.ns_labels = ns_labels
        self.labels = labels

    def match(self, resource_info):
        return label_matched(self.ns_labels, resource_info.ns_labels) and label_matched(self.labels,
                                                                                        resource_info.rsc_labels)


class ResourceInfo:

    def __init__(self, uuid, rsc_type, ns_name, ns_labels, rsc_name, rsc_labels):
        self.uuid = uuid
        self.rsc_type = rsc_type
        self.ns_name = ns_name
        self.ns_labels = ns_labels
        self.rsc_name = rsc_name
        self.rsc_labels = rsc_labels

    def get_canonical_name(self):
        return f"{self.rsc_type.name.lower()}-{self.rsc_name}-{self.ns_name}"


class JudgeResult(Enum):
    NOT_MATCHED = 1
    ALLOW = 2
    DENY = 3


class FlowState(Enum):
    NO_MATCH = 1
    ALLOWED = 2
    DENIED = 3


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

    def judge_flow(self, fr_rsc_info, to_rsc_info, port, direction):
        # if the policy don't apply to the pod, return None
        inside_resource_info = to_rsc_info if direction == Direction.INGRESS else fr_rsc_info
        if not (label_matched(self.inside_labels,
                              inside_resource_info.rsc_labels) and self.ns_name == inside_resource_info.ns_name):
            return JudgeResult.NOT_MATCHED

        # If the policy does not have this direction in policyTypes, the flow is allowed
        if direction.name.lower() not in self.policy_types:
            return JudgeResult.ALLOW

        # Judge if the flow is allowed by the rules
        rules = self.ingress_rules if direction == Direction.INGRESS else self.egress_rules
        outside_resource_info = fr_rsc_info if direction == Direction.INGRESS else to_rsc_info
        for rule in rules:
            if rule.judge_flow(outside_resource_info, port):
                return JudgeResult.ALLOW
        return JudgeResult.DENY

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


class ResourceType(Enum):
    PROC = 1
    CTN = 2
    POD = 3
    DEP = 4


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


def compare(static_policy_dicts, report, target_uuid, ignored_namespaces):
    proc_to_rsc = {}
    enp_to_rsc = {}
    enp_to_adj = {}
    enp_to_info = {}
    rsc_to_info = {}
    ns_name_to_labels = {}

    static_policies = {}
    for policy_dict in static_policy_dicts:
        policy = Policy.read_from_dict(policy_dict)
        static_policies[policy.name] = policy

    enps = report["Endpoint"]["nodes"]
    procs = report["Process"]["nodes"]
    ctns = report["Container"]["nodes"]
    pods = report["Pod"]["nodes"]
    deps = report["Deployment"]["nodes"]
    namespaces = report["Namespace"]["nodes"]

    for ns_id, ns_info in namespaces.items():
        ns_latest_info = ns_info["latest"]
        ns_name = ns_latest_info[POD_NAME_KEY]["value"]
        ns_labels = parse_labels(ns_latest_info)
        ns_name_to_labels[ns_name] = ns_labels

    for proc_id, proc_info in procs.items():
        # check if the process has a container
        ctn_id = get_parent_id(proc_info, "container")
        # if the process don't have a container, use process as the resource
        # process have no pod labels and namespace labels
        if ctn_id not in ctns:
            proc_latest_info = proc_info["latest"] if "latest" in proc_info else {}
            if proc_id not in rsc_to_info:
                rsc_name = proc_latest_info[PROC_NAME_KEY]["value"] if PROC_NAME_KEY in proc_latest_info else ""
                rsc_info = ResourceInfo("", ResourceType.PROC, "", {}, rsc_name, {})
                rsc_to_info[proc_id] = rsc_info
            proc_to_rsc[proc_id] = proc_id
            continue

        ctn_latest_info = ctns[ctn_id]["latest"]

        # check if the container has a pod
        pod_id = get_parent_id(ctns[ctn_id], "pod")
        # if the container don't have a pod, use container as the resource
        # container have no pod labels but may have namespace labels
        if pod_id not in pods:
            if ctn_id not in rsc_to_info:
                uuid = ctn_latest_info[CTN_UUID_KEY]["value"] if CTN_UUID_KEY in ctn_latest_info else ""
                ns_name = ctn_latest_info[CTN_NAMESPACE_KEY]["value"] if CTN_NAMESPACE_KEY in ctn_latest_info else ""
                ns_labels = ns_name_to_labels[ns_name] if ns_name in ns_name_to_labels else {}
                rsc_name = ctn_latest_info[CTN_NAME_KEY]["value"] if CTN_NAME_KEY in ctn_latest_info else ""
                rsc_info = ResourceInfo(uuid, ResourceType.CTN, ns_name, ns_labels, rsc_name, {})
                rsc_to_info[ctn_id] = rsc_info
            proc_to_rsc[proc_id] = ctn_id
            continue

        pod_latest_info = pods[pod_id]["latest"]

        # if there is a pod, store the pod_labels, ns_name and ns_labels
        # these will be the same as its deployment
        # the only difference is the rsc_name
        uuid = pod_latest_info[POD_UUID_KEY]["value"] if POD_UUID_KEY in pod_latest_info else ""
        ns_name = pod_latest_info[POD_NAMESPACE_KEY]["value"] if POD_NAMESPACE_KEY in pod_latest_info else ""
        ns_labels = ns_name_to_labels[ns_name] if ns_name in ns_name_to_labels else {}
        pod_labels = parse_labels(pod_latest_info)

        # check if the pod has a deployment
        dep_id = get_parent_id(pods[pod_id], "deployment")
        # if the pod don't have a deployment, use pod as the resource
        # pod have pod labels and namespace labels
        if dep_id not in deps:
            if pod_id not in rsc_to_info:
                rsc_name = pod_latest_info[POD_NAME_KEY]["value"] if POD_NAME_KEY in pod_latest_info else ""
                rsc_info = ResourceInfo(uuid, ResourceType.POD, ns_name, ns_labels, rsc_name, pod_labels)
                rsc_to_info[pod_id] = rsc_info
            proc_to_rsc[proc_id] = pod_id
            continue

        # if the pod have a deployment, use deployment as the resource
        # deployment have pod labels and namespace labels
        dep_latest_info = deps[dep_id]["latest"]
        if dep_id not in rsc_to_info:
            rsc_name = dep_latest_info[DEP_NAME_KEY]["value"] if DEP_NAME_KEY in dep_latest_info else ""
            rsc_to_info[dep_id] = ResourceInfo(uuid, ResourceType.DEP, ns_name, ns_labels, rsc_name, pod_labels)
        proc_to_rsc[proc_id] = dep_id

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
        if proc_id not in proc_to_rsc:
            continue
        enp_to_rsc[enp_id] = proc_to_rsc[proc_id]

    abnormal_flows = []

    # Go through all the flows to find the abnormal flows
    for fr_enp_id, fr_rsc_id in enp_to_rsc.items():
        to_enps = enp_to_adj[fr_enp_id]
        for to_enp_id in to_enps:
            if to_enp_id not in enp_to_rsc:
                continue
            to_rsc_id = enp_to_rsc[to_enp_id]
            if to_rsc_id == fr_rsc_id:
                continue
            to_rsc_info = rsc_to_info[to_rsc_id]
            fr_rsc_info = rsc_to_info[fr_rsc_id]

            # ignore the flows between ignored clusters
            if to_rsc_info.uuid != target_uuid and fr_rsc_info.uuid != target_uuid:
                continue

            # ignore the flows between ignored namespaces
            if to_rsc_info.ns_name in ignored_namespaces and fr_rsc_info.ns_name in ignored_namespaces:
                continue

            port = int(to_enp_id.split(";")[-1])

            ingress_state = FlowState.NO_MATCH
            egress_state = FlowState.NO_MATCH

            # the policies with the same canonical name will have higher priority
            # ingress test
            if to_rsc_info.get_canonical_name() in static_policies:
                policy = static_policies[to_rsc_info.get_canonical_name()]
                ingress_result = policy.judge_flow(fr_rsc_info, to_rsc_info, port, Direction.INGRESS)
                if ingress_result == JudgeResult.ALLOW:
                    ingress_state = FlowState.ALLOWED
                elif ingress_result == JudgeResult.DENY:
                    ingress_state = FlowState.DENIED
            # egress test
            if fr_rsc_info.get_canonical_name() in static_policies:
                policy = static_policies[fr_rsc_info.get_canonical_name()]
                egress_result = policy.judge_flow(fr_rsc_info, to_rsc_info, port, Direction.EGRESS)
                if egress_result == JudgeResult.ALLOW:
                    egress_state = FlowState.ALLOWED
                elif egress_result == JudgeResult.DENY:
                    egress_state = FlowState.DENIED
            if ingress_state == FlowState.ALLOWED and egress_state == FlowState.ALLOWED:
                continue

            # Fallback: go through all the policies
            for policy in static_policies.values():
                if ingress_state != FlowState.ALLOWED:
                    ingress_result = policy.judge_flow(fr_rsc_info, to_rsc_info, port, Direction.INGRESS)
                    if ingress_result == JudgeResult.ALLOW:
                        ingress_state = FlowState.ALLOWED
                    elif ingress_result == JudgeResult.DENY:
                        ingress_state = FlowState.DENIED

                if egress_state != FlowState.ALLOWED:
                    egress_result = policy.judge_flow(fr_rsc_info, to_rsc_info, port, Direction.EGRESS)
                    if egress_result == JudgeResult.ALLOW:
                        egress_state = FlowState.ALLOWED
                    elif egress_result == JudgeResult.DENY:
                        egress_state = FlowState.DENIED

                if ingress_state == FlowState.ALLOWED and egress_state == FlowState.ALLOWED:
                    break

            if ingress_state == FlowState.DENIED or egress_state == FlowState.DENIED:
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
